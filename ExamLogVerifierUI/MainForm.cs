using System.Globalization;
using System.Text;
using ExamShared;

namespace ExamLogVerifierUI;

/// <summary>
/// Teacher-facing GUI to verify many exam logs at once. Drag in exam folders or examlog.jsonl files,
/// load the exam.config (whose secret key signs the logs), and hit Verify. Each log turns green
/// (intact, clean), amber (soft warnings) or red (tampered or AI/forbidden-file incidents). Selecting
/// a log shows its events on the right, Finder-style, color-coded by severity.
/// </summary>
public sealed class MainForm : Form
{
    private enum StatusTier { Unverified, Ok, Warning, Red, Error }

    private sealed class LogItem
    {
        public string Path = "";
        public string Label = "";
        public LogVerificationResult? Result;
        public StatusTier Tier = StatusTier.Unverified;
        public bool Tampered;
        public int CriticalCount;
        public int WarningCount;
        public HashSet<string> EventTypes = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly List<(Control ctrl, string key)> _i18n = new();
    private readonly List<Button> _flagButtons = new();

    private readonly List<LogItem> _items = new();
    private byte[]? _logKey;
    private string? _configName;
    private bool _configValid;

    private readonly Label _titleLabel = new();
    private readonly Label _configLabel = new();
    private readonly Label _footerLabel = new();
    private readonly Label _rightHeader = new();
    private readonly Label _dropHint = new();

    private readonly DataGridView _logsGrid = new();
    private readonly DataGridView _eventsGrid = new();
    private readonly ComboBox _leftFilter = new();
    private readonly ComboBox _rightFilter = new();

    private readonly Button _btnConfig = new();
    private readonly Button _btnAddLogs = new();
    private readonly Button _btnAddFolder = new();
    private readonly Button _btnVerify = new();
    private readonly Button _btnClear = new();
    private readonly Button _btnExport = new();

    // Marker tags aligned with the left filter combo entries (null = "all").
    private string?[] _leftFilterTags = Array.Empty<string?>();

    private bool _building;
    private bool _suppressSelection;
    private bool _busy;

    private SplitContainer? _split;
    private bool _userMovedSplit;
    private bool _settingSplit;

    public MainForm()
    {
        Width = 1100;
        Height = 720;
        MinimumSize = new Size(880, 560);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.Background;
        Font = Theme.Base;
        ForeColor = Theme.Text;
        AllowDrop = true;
        DragEnter += OnDragEnter;
        DragDrop += OnDragDrop;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(14),
            ColumnCount = 1,
            RowCount = 5,
            BackColor = Theme.Background
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34)); // top bar
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));     // toolbar
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));     // config status
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // split
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 26)); // footer

        root.Controls.Add(BuildTopBar(), 0, 0);
        root.Controls.Add(BuildToolbar(), 0, 1);

        _configLabel.AutoSize = true;
        _configLabel.ForeColor = Theme.TextMuted;
        _configLabel.Margin = new Padding(2, 6, 0, 6);
        root.Controls.Add(_configLabel, 0, 2);

        root.Controls.Add(BuildSplit(), 0, 3);

        _footerLabel.Dock = DockStyle.Fill;
        _footerLabel.TextAlign = ContentAlignment.MiddleLeft;
        _footerLabel.ForeColor = Theme.TextMuted;
        root.Controls.Add(_footerLabel, 0, 4);

        Controls.Add(root);

        _building = true;
        ApplyLanguage();
        _building = false;

        RefreshLeft();
        UpdateFooter();
        RenderRightForSelection();
    }

    // ----- UI construction -----

    private Control BuildTopBar()
    {
        var bar = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Background
        };
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        _titleLabel.AutoSize = true;
        _titleLabel.Font = Theme.Heading;
        _titleLabel.ForeColor = Theme.Text;
        _titleLabel.TextAlign = ContentAlignment.MiddleLeft;
        _titleLabel.Margin = new Padding(2, 4, 0, 0);
        bar.Controls.Add(_titleLabel, 0, 0);

        var flags = new FlowLayoutPanel
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
            btn.Click += (_, _) => { Lang.Set(lang); ApplyLanguageGuarded(); };
            _flagButtons.Add(btn);
            flags.Controls.Add(btn);
        }

        bar.Controls.Add(flags, 1, 0);
        return bar;
    }

    private Control BuildToolbar()
    {
        var row = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            Margin = new Padding(0, 4, 0, 0),
            BackColor = Theme.Background
        };

        Theme.StylePrimary(_btnConfig);
        Theme.StyleSecondary(_btnAddLogs);
        Theme.StyleSecondary(_btnAddFolder);
        Theme.StyleSecondary(_btnVerify);
        Theme.StyleSecondary(_btnClear);
        Theme.StyleSecondary(_btnExport);

        _btnConfig.Click += async (_, _) => await LoadConfigDialog();
        _btnAddLogs.Click += async (_, _) => await AddLogsDialog();
        _btnAddFolder.Click += async (_, _) => await AddFolderDialog();
        _btnVerify.Click += async (_, _) => await RunBusy(VerifyAllCore);
        _btnClear.Click += (_, _) => ClearAll();
        _btnExport.Click += (_, _) => ExportSummary();

        L(_btnConfig, "btnLoadConfig");
        L(_btnAddLogs, "btnAddLogs");
        L(_btnAddFolder, "btnAddFolder");
        L(_btnVerify, "btnVerify");
        L(_btnClear, "btnClear");
        L(_btnExport, "btnExport");

        foreach (var b in new[] { _btnConfig, _btnAddLogs, _btnAddFolder, _btnVerify, _btnClear, _btnExport })
        {
            b.Margin = new Padding(0, 0, 8, 0);
            row.Controls.Add(b);
        }

        return row;
    }

    private Control BuildSplit()
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterWidth = 6,
            BackColor = Theme.Border,
            // Give it a valid width + splitter position BEFORE applying the min sizes: setting
            // Panel2MinSize re-validates SplitterDistance, which throws while the control still has
            // its tiny default size. Dock.Fill resizes it afterwards; ApplySplit re-clamps on layout.
            Size = new Size(1000, 600)
        };
        split.SplitterDistance = 420;
        split.Panel1MinSize = 280;
        split.Panel2MinSize = 320;
        _split = split;
        // Keep a ~42% split, clamped to the panels' min sizes, and re-applied on resize — until the
        // teacher drags the splitter themselves, after which we leave it where they put it.
        split.HandleCreated += (_, _) => ApplySplit();
        split.SizeChanged += (_, _) => ApplySplit();
        split.SplitterMoved += (_, _) => { if (!_settingSplit) _userMovedSplit = true; };

        split.Panel1.Controls.Add(BuildLeftPane());
        split.Panel2.Controls.Add(BuildRightPane());
        return split;
    }

    private void ApplySplit()
    {
        if (_split is null || _userMovedSplit)
        {
            return;
        }

        var min = _split.Panel1MinSize;
        var max = _split.Width - _split.Panel2MinSize - _split.SplitterWidth;
        if (max <= min)
        {
            return; // window too narrow right now; try again on the next resize
        }

        _settingSplit = true;
        try
        {
            _split.SplitterDistance = Math.Clamp((int)(_split.Width * 0.42), min, max);
        }
        catch
        {
            // Ignore transient sizing races.
        }
        finally
        {
            _settingSplit = false;
        }
    }

    private Control BuildLeftPane()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Surface,
            Padding = new Padding(0)
        };
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var filterRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Theme.Surface,
            Padding = new Padding(8, 8, 8, 6)
        };
        var leftFilterLabel = new Label { AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 6, 6, 0) };
        L(leftFilterLabel, "leftFilter");
        filterRow.Controls.Add(leftFilterLabel);
        Theme.StyleCombo(_leftFilter);
        _leftFilter.Width = 230;
        _leftFilter.SelectedIndexChanged += (_, _) => { if (!_building) RefreshLeft(); };
        filterRow.Controls.Add(_leftFilter);
        panel.Controls.Add(filterRow, 0, 0);

        var host = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };

        Theme.StyleGrid(_logsGrid);
        _logsGrid.Dock = DockStyle.Fill;
        _logsGrid.AllowDrop = true;
        _logsGrid.DragEnter += OnDragEnter;
        _logsGrid.DragDrop += OnDragDrop;
        _logsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "status",
            HeaderText = "",
            Width = 30,
            AutoSizeMode = DataGridViewAutoSizeColumnMode.None,
            DefaultCellStyle = { Alignment = DataGridViewContentAlignment.MiddleCenter, Font = Theme.Bold }
        });
        _logsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "name",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
            FillWeight = 46,
            DefaultCellStyle = { Font = Theme.Bold }
        });
        _logsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "summary",
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
            FillWeight = 54
        });
        _logsGrid.SelectionChanged += (_, _) => { if (!_suppressSelection) RenderRightForSelection(); };
        host.Controls.Add(_logsGrid);

        _dropHint.Dock = DockStyle.Fill;
        _dropHint.TextAlign = ContentAlignment.MiddleCenter;
        _dropHint.ForeColor = Theme.TextMuted;
        _dropHint.Font = Theme.Base;
        _dropHint.BackColor = Theme.Surface;
        _dropHint.AllowDrop = true;
        _dropHint.DragEnter += OnDragEnter;
        _dropHint.DragDrop += OnDragDrop;
        host.Controls.Add(_dropHint);

        panel.Controls.Add(host, 0, 1);
        return panel;
    }

    private Control BuildRightPane()
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Theme.Surface,
            Padding = new Padding(0)
        };
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var headerRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            AutoSize = true,
            BackColor = Theme.Surface,
            Padding = new Padding(10, 8, 10, 6)
        };
        headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        _rightHeader.AutoSize = true;
        _rightHeader.ForeColor = Theme.Text;
        _rightHeader.Font = Theme.Bold;
        _rightHeader.Margin = new Padding(0, 5, 0, 0);
        headerRow.Controls.Add(_rightHeader, 0, 0);

        var rightFilterPanel = new FlowLayoutPanel
        {
            Anchor = AnchorStyles.Right,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Theme.Surface
        };
        var rightFilterLabel = new Label { AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 6, 6, 0) };
        L(rightFilterLabel, "rightFilter");
        rightFilterPanel.Controls.Add(rightFilterLabel);
        Theme.StyleCombo(_rightFilter);
        _rightFilter.Width = 160;
        _rightFilter.SelectedIndexChanged += (_, _) => { if (!_building) RenderRightForSelection(); };
        rightFilterPanel.Controls.Add(_rightFilter);
        headerRow.Controls.Add(rightFilterPanel, 1, 0);

        panel.Controls.Add(headerRow, 0, 0);

        Theme.StyleGrid(_eventsGrid);
        _eventsGrid.Dock = DockStyle.Fill;
        _eventsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "line", HeaderText = "#", Width = 46, AutoSizeMode = DataGridViewAutoSizeColumnMode.None,
            DefaultCellStyle = { Alignment = DataGridViewContentAlignment.MiddleRight, ForeColor = Theme.TextMuted }
        });
        _eventsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "time", Width = 150, AutoSizeMode = DataGridViewAutoSizeColumnMode.None,
            DefaultCellStyle = { Font = Theme.Mono, ForeColor = Theme.TextMuted }
        });
        _eventsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "event", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, FillWeight = 36,
            DefaultCellStyle = { Font = Theme.Bold }
        });
        _eventsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "detail", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, FillWeight = 52
        });
        _eventsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = "chain", Width = 78, AutoSizeMode = DataGridViewAutoSizeColumnMode.None,
            DefaultCellStyle = { Alignment = DataGridViewContentAlignment.MiddleCenter }
        });
        panel.Controls.Add(_eventsGrid, 0, 1);
        return panel;
    }

    // ----- Language -----

    private void ApplyLanguageGuarded()
    {
        _building = true;
        ApplyLanguage();
        _building = false;
        RefreshLeft();
        UpdateFooter();
        RenderRightForSelection();
    }

    private void ApplyLanguage()
    {
        Text = Lang.T("title");
        _titleLabel.Text = Lang.T("title");

        foreach (var (ctrl, key) in _i18n)
        {
            ctrl.Text = Lang.T(key);
        }

        RebuildLeftFilter();
        RebuildRightFilter();
        UpdateConfigLabel();

        _logsGrid.Columns["name"]!.HeaderText = Lang.T("colName");
        _logsGrid.Columns["summary"]!.HeaderText = Lang.T("colSummary");
        _eventsGrid.Columns["time"]!.HeaderText = Lang.T("colTime");
        _eventsGrid.Columns["event"]!.HeaderText = Lang.T("colEvent");
        _eventsGrid.Columns["detail"]!.HeaderText = Lang.T("colDetail");
        _eventsGrid.Columns["chain"]!.HeaderText = Lang.T("colChain");

        _dropHint.Text = Lang.T("dropHint");

        foreach (var btn in _flagButtons)
        {
            var selected = (Language)btn.Tag! == Lang.Current;
            btn.FlatAppearance.BorderSize = selected ? 2 : 1;
            btn.FlatAppearance.BorderColor = selected ? Theme.Accent : Theme.Border;
        }
    }

    private void RebuildLeftFilter()
    {
        // Guard the SelectedIndexChanged handler while we mutate the combo; callers refresh after.
        var prevBuilding = _building;
        _building = true;

        var selectedTag = SelectedLeftFilterTag();

        _leftFilter.Items.Clear();
        var tags = new List<string?> { null, "__tampered", "__incidents" };
        _leftFilter.Items.Add(Lang.T("fAll"));
        _leftFilter.Items.Add(Lang.T("fTampered"));
        _leftFilter.Items.Add(Lang.T("fIncidents"));

        // Build the "Contain: <event>" entries from the event types actually present across the
        // loaded logs, so every event the teacher can see in the detail pane is also filterable.
        var present = _items
            .SelectMany(i => i.EventTypes)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(t => EventCatalog.Label(t), StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        foreach (var ev in present)
        {
            _leftFilter.Items.Add(string.Format(Lang.T("fContains"), EventCatalog.Label(ev)));
            tags.Add(ev);
        }

        _leftFilterTags = tags.ToArray();

        var restore = Array.IndexOf(_leftFilterTags, selectedTag);
        _leftFilter.SelectedIndex = restore >= 0 ? restore : 0;

        _building = prevBuilding;
    }

    private string? SelectedLeftFilterTag()
    {
        var idx = _leftFilter.SelectedIndex;
        return idx >= 0 && idx < _leftFilterTags.Length ? _leftFilterTags[idx] : null;
    }

    private void RebuildRightFilter()
    {
        var idx = _rightFilter.SelectedIndex;
        _rightFilter.Items.Clear();
        _rightFilter.Items.Add(Lang.T("efAll"));
        _rightFilter.Items.Add(Lang.T("efIncidents"));
        _rightFilter.Items.Add(Lang.T("efCritical"));
        _rightFilter.Items.Add(Lang.T("efWarnings"));
        _rightFilter.Items.Add(Lang.T("efInfo"));
        _rightFilter.SelectedIndex = idx < 0 || idx >= _rightFilter.Items.Count ? 0 : idx;
    }

    private T L<T>(T ctrl, string key) where T : Control
    {
        _i18n.Add((ctrl, key));
        ctrl.Text = Lang.T(key);
        return ctrl;
    }

    // ----- Config -----

    private async Task LoadConfigDialog()
    {
        using var dialog = new OpenFileDialog
        {
            Title = Lang.T("dlgConfig"),
            Filter = Lang.T("filterConfig"),
            FileName = "exam.config"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        TryLoadConfig(dialog.FileName);
        if (_logKey != null && _items.Count > 0)
        {
            await RunBusy(VerifyAllCore);
        }
    }

    private bool TryLoadConfig(string path)
    {
        try
        {
            var json = File.ReadAllText(path, Encoding.UTF8);
            var envelope = ConfigSerializer.DeserializeEnvelope(json);
            var payloadJson = ConfigSerializer.SerializePayload(envelope.Payload);
            var valid = ConfigIntegrityService.VerifyHmac(payloadJson, envelope.HmacBase64);
            var key = Convert.FromBase64String(envelope.Payload.LogSecretBase64);

            _logKey = key;
            _configName = Path.GetFileName(path);
            _configValid = valid;
            UpdateConfigLabel();
            return true;
        }
        catch (Exception ex)
        {
            _configLabel.ForeColor = Theme.RedText;
            _configLabel.Text = string.Format(Lang.T("configReadErr"), ex.Message);
            return false;
        }
    }

    private void UpdateConfigLabel()
    {
        if (_configName is null)
        {
            _configLabel.ForeColor = Theme.TextMuted;
            _configLabel.Text = Lang.T("configNone");
            return;
        }

        if (_configValid)
        {
            _configLabel.ForeColor = Theme.GreenText;
            _configLabel.Text = string.Format(Lang.T("configLoaded"), _configName);
        }
        else
        {
            _configLabel.ForeColor = Theme.RedText;
            _configLabel.Text = string.Format(Lang.T("configInvalid"), _configName);
        }
    }

    // ----- Adding logs -----

    private async Task AddLogsDialog()
    {
        using var dialog = new OpenFileDialog
        {
            Title = Lang.T("dlgLogs"),
            Filter = Lang.T("filterLogs"),
            Multiselect = true
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var files = dialog.FileNames;
            await RunBusy(() => ProcessPathsCore(files));
        }
    }

    private async Task AddFolderDialog()
    {
        using var dialog = new FolderBrowserDialog { Description = Lang.T("dlgFolder") };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var path = dialog.SelectedPath;
            await RunBusy(() => ProcessPathsCore(new[] { path }));
        }
    }

    private bool AddLog(string path)
    {
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch
        {
            return false;
        }

        if (_items.Any(i => string.Equals(i.Path, full, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        _items.Add(new LogItem { Path = full, Label = FolderLabel(full) });
        return true;
    }

    private static string FolderLabel(string fullPath)
    {
        var dir = Path.GetDirectoryName(fullPath);
        var name = string.IsNullOrEmpty(dir) ? "" : new DirectoryInfo(dir).Name;
        return name.Length > 0 ? name : Path.GetFileName(fullPath);
    }

    // ----- Busy / async orchestration -----

    // Runs an operation with the toolbar disabled and a wait cursor, keeping the message pump alive.
    // Re-entrant calls (e.g. a drop while a verify is running) are ignored rather than queued.
    private async Task RunBusy(Func<Task> work)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        UseWaitCursor = true;
        SetButtonsEnabled(false);
        try
        {
            await work();
        }
        catch (Exception ex)
        {
            // Never let an unexpected failure escape an async-void handler and crash the app.
            MessageBox.Show(this, string.Format(Lang.T("opErr"), ex.Message), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            SetButtonsEnabled(true);
            UseWaitCursor = false;
            _busy = false;
        }
    }

    private void SetButtonsEnabled(bool enabled)
    {
        foreach (var b in new[] { _btnConfig, _btnAddLogs, _btnAddFolder, _btnVerify, _btnClear, _btnExport })
        {
            b.Enabled = enabled;
        }
    }

    private sealed class ScanResult
    {
        public readonly List<string> Logs = new();
        public readonly List<string> DroppedConfigs = new();
        public string? FolderConfig;
        public bool SawFolder;
    }

    // Classifies dropped paths off the UI thread: a directory tree can be huge or live on a slow share.
    private static ScanResult ScanPaths(string[] paths)
    {
        var res = new ScanResult();
        foreach (var p in paths)
        {
            if (Directory.Exists(p))
            {
                res.SawFolder = true;
                res.Logs.AddRange(FindLogs(p));
                res.FolderConfig ??= FindFirstConfig(p);
            }
            else if (File.Exists(p))
            {
                var ext = Path.GetExtension(p).ToLowerInvariant();
                var name = Path.GetFileName(p).ToLowerInvariant();
                if (ext == ".config")
                {
                    res.DroppedConfigs.Add(p);
                }
                else if (ext == ".jsonl" || name == "examlog.jsonl")
                {
                    res.Logs.Add(p);
                }
            }
        }

        return res;
    }

    private async Task ProcessPathsCore(string[] paths)
    {
        var scan = await Task.Run(() => ScanPaths(paths));

        foreach (var cfg in scan.DroppedConfigs)
        {
            TryLoadConfig(cfg);
        }

        var added = 0;
        foreach (var log in scan.Logs)
        {
            if (AddLog(log))
            {
                added++;
            }
        }

        if (_logKey is null && scan.FolderConfig != null)
        {
            TryLoadConfig(scan.FolderConfig);
        }

        if (_logKey != null && _items.Count > 0)
        {
            await VerifyAllCore();
        }
        else
        {
            RebuildLeftFilter();
            RefreshLeft();
            UpdateFooter();
        }

        if (added == 0 && scan.SawFolder && scan.DroppedConfigs.Count == 0)
        {
            MessageBox.Show(this, Lang.T("noLogsFound"), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void ClearAll()
    {
        _items.Clear();
        RebuildLeftFilter();
        RefreshLeft();
        UpdateFooter();
        RenderRightForSelection();
    }

    // ----- Drag & drop -----

    private void OnDragEnter(object? sender, DragEventArgs e)
    {
        if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
        {
            e.Effect = DragDropEffects.Copy;
        }
    }

    private async void OnDragDrop(object? sender, DragEventArgs e)
    {
        if (e.Data?.GetData(DataFormats.FileDrop) is not string[] paths)
        {
            return;
        }

        await RunBusy(() => ProcessPathsCore(paths));
    }

    // Manual recursive walk so a single access-denied subfolder does not abort the whole scan.
    private static IEnumerable<string> FindLogs(string root)
    {
        var results = new List<string>();
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir, "examlog.jsonl"))
                {
                    results.Add(f);
                }

                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    stack.Push(sub);
                }
            }
            catch
            {
                // Skip folders we cannot read.
            }
        }

        return results;
    }

    private static string? FindFirstConfig(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir, "*.config"))
                {
                    return f;
                }

                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    stack.Push(sub);
                }
            }
            catch
            {
                // Skip unreadable folders.
            }
        }

        return null;
    }

    // ----- Verification -----

    private async Task VerifyAllCore()
    {
        if (_logKey is null)
        {
            MessageBox.Show(this, Lang.T("needConfig"), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (_items.Count == 0)
        {
            MessageBox.Show(this, Lang.T("noLogsToVerify"), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var key = _logKey;
        var snapshot = _items.ToList();

        // The CPU/IO-bound chain check runs off the UI thread; we resume here to update the grid.
        var computed = await Task.Run(() =>
            snapshot.Select(it => (item: it, result: LogVerifier.Verify(it.Path, key))).ToList());

        foreach (var (item, r) in computed)
        {
            ApplyResult(item, r);
        }

        RebuildLeftFilter();
        RefreshLeft();
        UpdateFooter();
        RenderRightForSelection();
        MaybeAdviseMismatch();
    }

    private static void ApplyResult(LogItem item, LogVerificationResult r)
    {
        item.Result = r;
        item.EventTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        item.CriticalCount = 0;
        item.WarningCount = 0;
        item.Tampered = r.Integrity == LogIntegrity.Tampered;

        if (!r.ReadOk)
        {
            item.Tier = StatusTier.Error;
            return;
        }

        foreach (var e in r.Entries)
        {
            var type = e.Entry.EventType;
            item.EventTypes.Add(type);
            var sev = EventCatalog.SeverityOf(type);
            if (sev == Severity.Critical)
            {
                item.CriticalCount++;
            }
            else if (sev == Severity.Warning)
            {
                item.WarningCount++;
            }
        }

        // An empty log is treated as red: a genuine client always writes startup events, so a blank
        // examlog.jsonl means it was deleted or wiped — it must never be waved through as "OK".
        if (item.Tampered || item.CriticalCount > 0 || r.Integrity == LogIntegrity.Empty)
        {
            item.Tier = StatusTier.Red;
        }
        else if (item.WarningCount > 0)
        {
            item.Tier = StatusTier.Warning;
        }
        else
        {
            item.Tier = StatusTier.Ok;
        }
    }

    // When every verifiable log fails from its very first line, the loaded exam.config almost
    // certainly does not belong to these logs (wrong key) rather than every student tampering.
    private void MaybeAdviseMismatch()
    {
        var verifiable = _items
            .Where(i => i.Result is { ReadOk: true } && i.Result.Entries.Count > 0)
            .ToList();

        if (verifiable.Count >= 2 && verifiable.All(i => i.Result!.Entries.All(e => !e.Valid)))
        {
            MessageBox.Show(this, Lang.T("mismatchMsg"), Lang.T("mismatchTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    // ----- Left list rendering -----

    private bool LeftFilterAccepts(LogItem item)
    {
        var idx = _leftFilter.SelectedIndex;
        if (idx < 0 || idx >= _leftFilterTags.Length)
        {
            return true;
        }

        var tag = _leftFilterTags[idx];
        return tag switch
        {
            null => true,
            "__tampered" => item.Tampered,
            "__incidents" => item.CriticalCount > 0 || item.WarningCount > 0,
            _ => item.EventTypes.Contains(tag)
        };
    }

    private void RefreshLeft()
    {
        _suppressSelection = true;
        var previouslySelected = SelectedItem();

        _logsGrid.SuspendLayout();
        _logsGrid.Rows.Clear();

        foreach (var item in _items)
        {
            if (!LeftFilterAccepts(item))
            {
                continue;
            }

            var bg = TierBg(item.Tier);
            var dot = TierColor(item.Tier);
            var idx = _logsGrid.Rows.Add("●", item.Label, SummaryText(item));
            var row = _logsGrid.Rows[idx];
            row.Tag = item;
            row.DefaultCellStyle.BackColor = bg;
            row.DefaultCellStyle.SelectionBackColor = Darken(bg, 0.10);
            row.Cells[0].Style.ForeColor = dot;
            row.Cells[0].Style.SelectionForeColor = dot;
            row.Cells[1].ToolTipText = item.Path;
            row.Cells[2].Style.ForeColor = TierTextColor(item.Tier);
            row.Cells[2].Style.SelectionForeColor = TierTextColor(item.Tier);
        }

        _logsGrid.ResumeLayout();
        _logsGrid.ClearSelection();

        var hasRows = _logsGrid.Rows.Count > 0;
        _dropHint.Visible = !hasRows;
        if (!hasRows)
        {
            _dropHint.BringToFront();
        }

        // Restore selection to the same item if still visible, else select the first row.
        if (hasRows)
        {
            var target = 0;
            if (previouslySelected != null)
            {
                for (var i = 0; i < _logsGrid.Rows.Count; i++)
                {
                    if (ReferenceEquals(_logsGrid.Rows[i].Tag, previouslySelected))
                    {
                        target = i;
                        break;
                    }
                }
            }

            _logsGrid.Rows[target].Selected = true;
            _logsGrid.CurrentCell = _logsGrid.Rows[target].Cells[1];
        }

        _suppressSelection = false;
        RenderRightForSelection();
    }

    private string SummaryText(LogItem item)
    {
        switch (item.Tier)
        {
            case StatusTier.Unverified:
                return Lang.T("sumUnverified");
            case StatusTier.Error:
                return Lang.T("sumError");
        }

        if (item.Tampered)
        {
            var line = item.Result?.FirstBrokenLine ?? -1;
            return string.Format(Lang.T("sumTampered"), line);
        }

        if (item.CriticalCount > 0 || item.WarningCount > 0)
        {
            var parts = new List<string>();
            if (item.CriticalCount > 0)
            {
                parts.Add(string.Format(Lang.T("sumCrit"), item.CriticalCount));
            }

            if (item.WarningCount > 0)
            {
                parts.Add(string.Format(Lang.T("sumWarn"), item.WarningCount));
            }

            return string.Join(" · ", parts);
        }

        if (item.Result?.Integrity == LogIntegrity.Empty)
        {
            return Lang.T("sumEmpty");
        }

        return Lang.T("sumOk");
    }

    // ----- Right detail rendering -----

    private LogItem? SelectedItem()
    {
        if (_logsGrid.SelectedRows.Count > 0)
        {
            return _logsGrid.SelectedRows[0].Tag as LogItem;
        }

        return null;
    }

    private void RenderRightForSelection()
    {
        var item = SelectedItem();
        _eventsGrid.SuspendLayout();
        _eventsGrid.Rows.Clear();

        if (item is null)
        {
            _rightHeader.ForeColor = Theme.TextMuted;
            _rightHeader.Text = Lang.T("selectHint");
            _eventsGrid.ResumeLayout();
            return;
        }

        if (item.Result is null || item.Tier == StatusTier.Unverified)
        {
            _rightHeader.ForeColor = Theme.TextMuted;
            _rightHeader.Text = Lang.T("needConfig");
            _eventsGrid.ResumeLayout();
            return;
        }

        if (!item.Result.ReadOk)
        {
            _rightHeader.ForeColor = Theme.RedText;
            _rightHeader.Text = string.Format(Lang.T("configReadErr"), item.Result.Error ?? "");
            _eventsGrid.ResumeLayout();
            return;
        }

        var shown = 0;
        foreach (var e in item.Result.Entries)
        {
            if (!RightFilterAccepts(e))
            {
                continue;
            }

            var sev = EventCatalog.SeverityOf(e.Entry.EventType);
            var idx = _eventsGrid.Rows.Add(
                e.LineNumber.ToString(CultureInfo.InvariantCulture),
                FormatTime(e.Entry.Timestamp),
                EventCatalog.Label(e.Entry.EventType),
                e.Entry.EventData ?? "",
                e.Valid ? Lang.T("chainCellOk") : Lang.T("chainCellBad"));

            var row = _eventsGrid.Rows[idx];
            if (!e.Valid)
            {
                row.DefaultCellStyle.BackColor = Theme.RedBg;
                row.DefaultCellStyle.SelectionBackColor = Darken(Theme.RedBg, 0.10);
                row.Cells[4].Style.ForeColor = Theme.RedText;
                row.Cells[4].Style.Font = Theme.Bold;
            }
            else
            {
                var bg = EventCatalog.RowBg(sev);
                row.DefaultCellStyle.BackColor = bg;
                row.DefaultCellStyle.SelectionBackColor = Darken(bg, 0.08);
                row.Cells[4].Style.ForeColor = Theme.GreenText;
            }

            row.Cells[2].Style.ForeColor = EventCatalog.RowText(sev);
            row.Cells[2].Style.SelectionForeColor = EventCatalog.RowText(sev);
            shown++;
        }

        _eventsGrid.ResumeLayout();

        var integrity = item.Tampered
            ? string.Format(Lang.T("chainBroken"), item.Result.FirstBrokenLine)
            : Lang.T("chainIntact");
        _rightHeader.ForeColor = item.Tampered ? Theme.RedText : Theme.TextMuted;
        _rightHeader.Text = string.Format(Lang.T("hdrSelected"), item.Label, shown) + "  ·  " + integrity;
    }

    private bool RightFilterAccepts(VerifiedLogEntry e)
    {
        var sev = EventCatalog.SeverityOf(e.Entry.EventType);
        return _rightFilter.SelectedIndex switch
        {
            1 => sev is Severity.Critical or Severity.Warning, // incidents
            2 => sev == Severity.Critical,
            3 => sev == Severity.Warning,
            4 => sev is Severity.Info or Severity.Good, // routine, non-incident lines
            _ => true
        };
    }

    private static string FormatTime(string iso)
    {
        if (DateTime.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt))
        {
            return dt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        }

        return iso;
    }

    // ----- Footer & export -----

    private void UpdateFooter()
    {
        var total = _items.Count;
        var ok = _items.Count(i => i.Tier == StatusTier.Ok);
        var tampered = _items.Count(i => i.Tampered);
        // Everything red-but-not-tampered (critical incidents, empty logs) plus amber warnings.
        var incidents = _items.Count(i => i.Tier == StatusTier.Warning || (i.Tier == StatusTier.Red && !i.Tampered));
        var unverified = _items.Count(i => i.Tier is StatusTier.Unverified or StatusTier.Error);

        var text = string.Format(Lang.T("footer"), total, ok, incidents, tampered, unverified);
        if (_configName != null && !_configValid)
        {
            text += Lang.T("footerCfgWarn");
        }

        _footerLabel.Text = text;
        _footerLabel.ForeColor = _configName != null && !_configValid ? Theme.RedText : Theme.TextMuted;
    }

    private void ExportSummary()
    {
        if (_items.Count == 0)
        {
            MessageBox.Show(this, Lang.T("noLogsToVerify"), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = Lang.T("exportTitle"),
            Filter = "CSV (*.csv)|*.csv|All files (*.*)|*.*",
            FileName = "exam-log-summary.csv"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            var sb = new StringBuilder();
            sb.AppendLine(Lang.T("csvHeader"));
            foreach (var i in _items)
            {
                var status = i.Tier switch
                {
                    StatusTier.Ok => "OK",
                    StatusTier.Warning => "WARNINGS",
                    StatusTier.Red => i.Tampered ? "TAMPERED" : "INCIDENTS",
                    StatusTier.Error => "ERROR",
                    _ => "UNVERIFIED"
                };
                var broken = i.Result?.FirstBrokenLine ?? -1;
                sb.AppendLine(string.Join(",",
                    Csv(i.Label), Csv(i.Path), status,
                    i.CriticalCount.ToString(CultureInfo.InvariantCulture),
                    i.WarningCount.ToString(CultureInfo.InvariantCulture),
                    broken.ToString(CultureInfo.InvariantCulture)));
            }

            File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
            MessageBox.Show(this, string.Format(Lang.T("exportOk"), dialog.FileName), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, string.Format(Lang.T("exportErr"), ex.Message), Lang.T("msgTitle"),
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string Csv(string field)
    {
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n'))
        {
            return "\"" + field.Replace("\"", "\"\"") + "\"";
        }

        return field;
    }

    // ----- Tier colors -----

    private static Color TierColor(StatusTier tier) => tier switch
    {
        StatusTier.Ok => Theme.GreenText,
        StatusTier.Warning => Theme.AmberText,
        StatusTier.Red => Theme.RedText,
        StatusTier.Error => Theme.RedText,
        _ => Theme.TextMuted
    };

    private static Color TierTextColor(StatusTier tier) => tier switch
    {
        StatusTier.Ok => Theme.GreenText,
        StatusTier.Warning => Theme.AmberText,
        StatusTier.Red => Theme.RedText,
        StatusTier.Error => Theme.RedText,
        _ => Theme.TextMuted
    };

    private static Color TierBg(StatusTier tier) => tier switch
    {
        StatusTier.Ok => Theme.GreenBg,
        StatusTier.Warning => Theme.AmberBg,
        StatusTier.Red => Theme.RedBg,
        StatusTier.Error => Theme.RedBg,
        _ => Theme.InfoBg
    };

    private static Color Darken(Color c, double f) =>
        Color.FromArgb(c.A,
            (int)Math.Max(0, c.R * (1 - f)),
            (int)Math.Max(0, c.G * (1 - f)),
            (int)Math.Max(0, c.B * (1 - f)));
}
