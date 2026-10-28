using System.Globalization;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ExamDesktop.Ui;
using ExamShared;
using AppTheme = ExamLogVerifierUI.Theme;

namespace ExamLogVerifierUI;

/// <summary>
/// Avalonia port of the teacher GUI that verifies many exam logs at once. Drop in exam folders or
/// examlog.jsonl files, load the exam.config (whose secret key signs the logs), and hit Verify. Each
/// log turns green (intact, clean), amber (soft warnings) or red (tampered or AI/forbidden-file
/// incidents). Selecting a log shows its events on the right, color-coded by severity.
/// </summary>
public sealed class MainWindow : Window
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

    private sealed record LogLine(LogItem Item, string Summary);

    private sealed record EventLine(string Line, string Time, string Event, string Detail, string Chain,
        IBrush Back, IBrush EventFore, IBrush ChainFore, bool ChainBold);

    private const string LogColumns = "30,2*,3*";
    private const string EventColumns = "46,190,2.2*,3*,70";

    private readonly List<(Control ctrl, string key)> _i18n = new();
    private readonly LanguageBar _languageBar;

    private readonly List<LogItem> _items = new();
    private byte[]? _logKey;
    private string? _configName;
    private bool _configValid;

    private readonly TextBlock _titleLabel = new() { FontSize = 20, FontWeight = FontWeight.SemiBold, Foreground = Palette.Text, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _configLabel = Ui.Muted();
    private readonly TextBlock _footerLabel = Ui.Muted();
    private readonly TextBlock _rightHeader = new() { FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _dropHint = Ui.Muted();

    private readonly ListBox _logsGrid = Ui.TableRows(new ListBox());
    private readonly ListBox _eventsGrid = Ui.TableRows(new ListBox());
    private readonly TextBlock[] _logHeaders = new TextBlock[3];
    private readonly TextBlock[] _eventHeaders = new TextBlock[5];
    private readonly ComboBox _leftFilter = new() { MinWidth = 230 };
    private readonly ComboBox _rightFilter = new() { MinWidth = 160 };

    private readonly Button _btnConfig = Ui.Primary(new Button());
    private readonly Button _btnAddLogs = Ui.Secondary(new Button());
    private readonly Button _btnAddFolder = Ui.Secondary(new Button());
    private readonly Button _btnVerify = Ui.Secondary(new Button());
    private readonly Button _btnClear = Ui.Secondary(new Button());
    private readonly Button _btnExport = Ui.Secondary(new Button());

    // Marker tags aligned with the left filter combo entries (null = "all").
    private string?[] _leftFilterTags = Array.Empty<string?>();

    private bool _building;
    private bool _suppressSelection;
    private bool _busy;

    /// <param name="startupPaths">Folders, logs or exam.config passed on the command line ("Open with…").</param>
    public MainWindow(string[]? startupPaths = null)
    {
        Width = 1140;
        Height = 740;
        MinWidth = 760;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Palette.Background;

        _languageBar = new LanguageBar(i => { Lang.Set((Language)i); ApplyLanguageGuarded(); });

        var topBar = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        topBar.Children.Add(Ui.Cell(_titleLabel, 0, 0));
        topBar.Children.Add(Ui.Cell(_languageBar, 0, 1));

        _configLabel.Margin = new Thickness(2, 8, 0, 8);
        _footerLabel.Margin = new Thickness(2, 8, 0, 0);

        var root = new Grid { Margin = new Thickness(14), RowDefinitions = new RowDefinitions("Auto,Auto,Auto,*,Auto") };
        root.Children.Add(Ui.Cell(topBar, 0));
        root.Children.Add(Ui.Cell(BuildToolbar(), 1));
        root.Children.Add(Ui.Cell(_configLabel, 2));
        root.Children.Add(Ui.Cell(BuildSplit(), 3));
        root.Children.Add(Ui.Cell(_footerLabel, 4));
        Content = root;

        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DropEvent, OnDrop);

        _building = true;
        ApplyLanguage();
        _building = false;

        RefreshLeft();
        UpdateFooter();
        RenderRightForSelection();

        var paths = startupPaths?.Where(p => File.Exists(p) || Directory.Exists(p)).ToArray() ?? Array.Empty<string>();
        if (paths.Length > 0)
        {
            Opened += async (_, _) => await RunBusy(() => ProcessPathsCore(paths));
        }
    }

    // ----- UI construction -----

    private Control BuildToolbar()
    {
        _btnConfig.Click += async (_, _) => await LoadConfigDialog();
        _btnAddLogs.Click += async (_, _) => await AddLogsDialog();
        _btnAddFolder.Click += async (_, _) => await AddFolderDialog();
        _btnVerify.Click += async (_, _) => await RunBusy(VerifyAllCore);
        _btnClear.Click += (_, _) => ClearAll();
        _btnExport.Click += async (_, _) => await ExportSummary();

        L(_btnConfig, "btnLoadConfig");
        L(_btnAddLogs, "btnAddLogs");
        L(_btnAddFolder, "btnAddFolder");
        L(_btnVerify, "btnVerify");
        L(_btnClear, "btnClear");
        L(_btnExport, "btnExport");

        var row = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
        foreach (var b in new[] { _btnConfig, _btnAddLogs, _btnAddFolder, _btnVerify, _btnClear, _btnExport })
        {
            b.Margin = new Thickness(0, 0, 8, 4);
            row.Children.Add(b);
        }

        return row;
    }

    private Control BuildSplit()
    {
        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("42*,6,58*") };
        split.ColumnDefinitions[0].MinWidth = 280;
        split.ColumnDefinitions[2].MinWidth = 320;
        split.Children.Add(Ui.Cell(Pane(BuildLeftPane()), 0, 0));
        split.Children.Add(Ui.Cell(new GridSplitter { Background = Brushes.Transparent, ResizeDirection = GridResizeDirection.Columns }, 0, 1));
        split.Children.Add(Ui.Cell(Pane(BuildRightPane()), 0, 2));
        return split;
    }

    private static Border Pane(Control child) => new()
    {
        Background = Palette.Surface,
        BorderBrush = Palette.Border,
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(6),
        ClipToBounds = true,
        Child = child
    };

    private static Grid HeaderRow(string columns, TextBlock[] cells)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(columns), Background = Palette.Background };
        for (var i = 0; i < cells.Length; i++)
        {
            cells[i] = new TextBlock { Foreground = Palette.TextMuted, FontWeight = FontWeight.SemiBold, Margin = new Thickness(6, 6), TextTrimming = TextTrimming.CharacterEllipsis };
            grid.Children.Add(Ui.Cell(cells[i], 0, i));
        }

        return grid;
    }

    private static TextBlock GridCell(string text, IBrush fore, bool bold = false, TextAlignment align = TextAlignment.Left, FontFamily? font = null)
    {
        var cell = new TextBlock
        {
            Text = text,
            Foreground = fore,
            FontWeight = bold ? FontWeight.SemiBold : FontWeight.Normal,
            TextAlignment = align,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(6, 5),
            VerticalAlignment = VerticalAlignment.Center
        };
        if (font is not null)
        {
            cell.FontFamily = font;
        }

        return cell;
    }

    private Control BuildLeftPane()
    {
        var filterRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Margin = new Thickness(8, 8, 8, 6) };
        var leftFilterLabel = Ui.Muted();
        leftFilterLabel.VerticalAlignment = VerticalAlignment.Center;
        L(leftFilterLabel, "leftFilter");
        filterRow.Children.Add(leftFilterLabel);
        _leftFilter.SelectionChanged += (_, _) => { if (!_building) RefreshLeft(); };
        filterRow.Children.Add(_leftFilter);

        _logsGrid.Background = Palette.Surface;
        _logsGrid.ItemTemplate = new FuncDataTemplate<LogLine>((line, _) =>
        {
            var item = line.Item;
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(LogColumns), Background = TierBg(item.Tier).ToBrush() };
            grid.Children.Add(Ui.Cell(GridCell("●", TierColor(item.Tier).ToBrush(), bold: true, align: TextAlignment.Center), 0, 0));
            var name = GridCell(item.Label, Palette.Text, bold: true);
            ToolTip.SetTip(name, item.Path);
            grid.Children.Add(Ui.Cell(name, 0, 1));
            var summary = GridCell(line.Summary, TierColor(item.Tier).ToBrush());
            ToolTip.SetTip(summary, line.Summary);
            grid.Children.Add(Ui.Cell(summary, 0, 2));
            return grid;
        });
        _logsGrid.SelectionChanged += (_, _) => { if (!_suppressSelection) RenderRightForSelection(); };

        _dropHint.TextAlignment = TextAlignment.Center;
        _dropHint.HorizontalAlignment = HorizontalAlignment.Center;
        _dropHint.VerticalAlignment = VerticalAlignment.Center;
        _dropHint.Margin = new Thickness(20);
        _dropHint.IsHitTestVisible = false;

        var host = new Grid();
        host.Children.Add(_logsGrid);
        host.Children.Add(_dropHint);

        var panel = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*") };
        panel.Children.Add(Ui.Cell(filterRow, 0));
        panel.Children.Add(Ui.Cell(HeaderRow(LogColumns, _logHeaders), 1));
        panel.Children.Add(Ui.Cell(host, 2));
        return panel;
    }

    private Control BuildRightPane()
    {
        var rightFilterLabel = Ui.Muted();
        rightFilterLabel.VerticalAlignment = VerticalAlignment.Center;
        L(rightFilterLabel, "rightFilter");
        _rightFilter.SelectionChanged += (_, _) => { if (!_building) RenderRightForSelection(); };

        var headerRow = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(10, 8, 10, 6) };
        headerRow.Children.Add(Ui.Cell(_rightHeader, 0, 0));
        headerRow.Children.Add(Ui.Cell(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Children = { rightFilterLabel, _rightFilter } }, 0, 1));

        var mono = new FontFamily("DejaVu Sans Mono, Consolas, monospace");
        _eventsGrid.Background = Palette.Surface;
        _eventsGrid.ItemTemplate = new FuncDataTemplate<EventLine>((line, _) =>
        {
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(EventColumns), Background = line.Back };
            grid.Children.Add(Ui.Cell(GridCell(line.Line, Palette.TextMuted, align: TextAlignment.Right), 0, 0));
            grid.Children.Add(Ui.Cell(GridCell(line.Time, Palette.TextMuted, font: mono), 0, 1));
            grid.Children.Add(Ui.Cell(GridCell(line.Event, line.EventFore, bold: true), 0, 2));
            var detail = GridCell(line.Detail, Palette.Text);
            ToolTip.SetTip(detail, line.Detail);
            grid.Children.Add(Ui.Cell(detail, 0, 3));
            grid.Children.Add(Ui.Cell(GridCell(line.Chain, line.ChainFore, bold: line.ChainBold, align: TextAlignment.Center), 0, 4));
            return grid;
        });

        var panel = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*") };
        panel.Children.Add(Ui.Cell(headerRow, 0));
        panel.Children.Add(Ui.Cell(HeaderRow(EventColumns, _eventHeaders), 1));
        panel.Children.Add(Ui.Cell(_eventsGrid, 2));
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
        Title = Lang.T("title");
        _titleLabel.Text = Lang.T("title");

        foreach (var (ctrl, key) in _i18n)
        {
            switch (ctrl)
            {
                case TextBlock t: t.Text = Lang.T(key); break;
                case ContentControl c: c.Content = Lang.T(key); break;
            }
        }

        RebuildLeftFilter();
        RebuildRightFilter();
        UpdateConfigLabel();

        _logHeaders[0].Text = "";
        _logHeaders[1].Text = Lang.T("colName");
        _logHeaders[2].Text = Lang.T("colSummary");
        _eventHeaders[0].Text = "#";
        _eventHeaders[1].Text = Lang.T("colTime");
        _eventHeaders[2].Text = Lang.T("colEvent");
        _eventHeaders[3].Text = Lang.T("colDetail");
        _eventHeaders[4].Text = Lang.T("colChain");

        _dropHint.Text = Lang.T("dropHint");
        _languageBar.Select((int)Lang.Current);
    }

    private void RebuildLeftFilter()
    {
        // Guard the SelectionChanged handler while we mutate the combo; callers refresh after.
        var prevBuilding = _building;
        _building = true;

        var selectedTag = SelectedLeftFilterTag();

        var labels = new List<string> { Lang.T("fAll"), Lang.T("fTampered"), Lang.T("fIncidents") };
        var tags = new List<string?> { null, "__tampered", "__incidents" };

        // Build the "Contain: <event>" entries from the event types actually present across the
        // loaded logs, so every event the teacher can see in the detail pane is also filterable.
        var present = _items
            .SelectMany(i => i.EventTypes)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(t => EventCatalog.Label(t), StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        foreach (var ev in present)
        {
            labels.Add(string.Format(Lang.T("fContains"), EventCatalog.Label(ev)));
            tags.Add(ev);
        }

        _leftFilterTags = tags.ToArray();
        _leftFilter.ItemsSource = labels;

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
        _rightFilter.ItemsSource = new[] { Lang.T("efAll"), Lang.T("efIncidents"), Lang.T("efCritical"), Lang.T("efWarnings"), Lang.T("efInfo") };
        _rightFilter.SelectedIndex = idx < 0 || idx >= 5 ? 0 : idx;
    }

    private T L<T>(T ctrl, string key) where T : Control
    {
        _i18n.Add((ctrl, key));
        return ctrl;
    }

    // ----- Config -----

    private async Task LoadConfigDialog()
    {
        var file = await Pickers.OpenFile(this, Lang.T("dlgConfig"), ("Config (*.config)", new[] { "*.config" }));
        if (file is null)
        {
            return;
        }

        TryLoadConfig(file);
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
            _configLabel.Foreground = Palette.RedText;
            _configLabel.Text = string.Format(Lang.T("configReadErr"), ex.Message);
            return false;
        }
    }

    private void UpdateConfigLabel()
    {
        if (_configName is null)
        {
            _configLabel.Foreground = Palette.TextMuted;
            _configLabel.Text = Lang.T("configNone");
            return;
        }

        if (_configValid)
        {
            _configLabel.Foreground = Palette.GreenText;
            _configLabel.Text = string.Format(Lang.T("configLoaded"), _configName);
        }
        else
        {
            _configLabel.Foreground = Palette.RedText;
            _configLabel.Text = string.Format(Lang.T("configInvalid"), _configName);
        }
    }

    // ----- Adding logs -----

    private async Task AddLogsDialog()
    {
        var files = await Pickers.OpenFiles(this, Lang.T("dlgLogs"), true, ("Log (*.jsonl)", new[] { "*.jsonl" }));
        if (files.Length > 0)
        {
            await RunBusy(() => ProcessPathsCore(files));
        }
    }

    private async Task AddFolderDialog()
    {
        var path = await Pickers.OpenFolder(this, Lang.T("dlgFolder"));
        if (path is not null)
        {
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

        // Linux paths are case-sensitive; Windows ones are not.
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (_items.Any(i => string.Equals(i.Path, full, comparison)))
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

    // Runs an operation with the toolbar disabled and a wait cursor, keeping the UI responsive.
    // Re-entrant calls (e.g. a drop while a verify is running) are ignored rather than queued.
    private async Task RunBusy(Func<Task> work)
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        Cursor = new Cursor(StandardCursorType.Wait);
        SetButtonsEnabled(false);
        try
        {
            await work();
        }
        catch (Exception ex)
        {
            // Never let an unexpected failure escape an async-void handler and crash the app.
            await MessageBox.Show(this, string.Format(Lang.T("opErr"), ex.Message), Lang.T("msgTitle"), MessageKind.Error);
        }
        finally
        {
            SetButtonsEnabled(true);
            Cursor = Cursor.Default;
            _busy = false;
        }
    }

    private void SetButtonsEnabled(bool enabled)
    {
        foreach (var b in new[] { _btnConfig, _btnAddLogs, _btnAddFolder, _btnVerify, _btnClear, _btnExport })
        {
            b.IsEnabled = enabled;
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
            await MessageBox.Show(this, Lang.T("noLogsFound"), Lang.T("msgTitle"));
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

    private static void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private async void OnDrop(object? sender, DragEventArgs e)
    {
        var paths = e.Data.GetFiles()?.Select(f => f.TryGetLocalPath()).OfType<string>().ToArray();
        if (paths is null || paths.Length == 0)
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
            await MessageBox.Show(this, Lang.T("needConfig"), Lang.T("msgTitle"), MessageKind.Warning);
            return;
        }

        if (_items.Count == 0)
        {
            await MessageBox.Show(this, Lang.T("noLogsToVerify"), Lang.T("msgTitle"));
            return;
        }

        var key = _logKey;
        var snapshot = _items.ToList();

        // The CPU/IO-bound chain check runs off the UI thread; we resume here to update the lists.
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
        await MaybeAdviseMismatch();
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
    private async Task MaybeAdviseMismatch()
    {
        var verifiable = _items
            .Where(i => i.Result is { ReadOk: true } && i.Result.Entries.Count > 0)
            .ToList();

        if (verifiable.Count >= 2 && verifiable.All(i => i.Result!.Entries.All(e => !e.Valid)))
        {
            await MessageBox.Show(this, Lang.T("mismatchMsg"), Lang.T("mismatchTitle"), MessageKind.Warning);
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

        var lines = _items.Where(LeftFilterAccepts).Select(i => new LogLine(i, SummaryText(i))).ToList();
        _logsGrid.ItemsSource = lines;
        _dropHint.IsVisible = lines.Count == 0;

        // Restore selection to the same item if still visible, else select the first row.
        _logsGrid.SelectedItem = lines.FirstOrDefault(l => ReferenceEquals(l.Item, previouslySelected)) ?? lines.FirstOrDefault();

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

    private LogItem? SelectedItem() => (_logsGrid.SelectedItem as LogLine)?.Item;

    private void RenderRightForSelection()
    {
        var item = SelectedItem();
        _eventsGrid.ItemsSource = null;

        if (item is null)
        {
            _rightHeader.Foreground = Palette.TextMuted;
            _rightHeader.Text = Lang.T("selectHint");
            return;
        }

        if (item.Result is null || item.Tier == StatusTier.Unverified)
        {
            _rightHeader.Foreground = Palette.TextMuted;
            _rightHeader.Text = Lang.T("needConfig");
            return;
        }

        if (!item.Result.ReadOk)
        {
            _rightHeader.Foreground = Palette.RedText;
            _rightHeader.Text = string.Format(Lang.T("configReadErr"), item.Result.Error ?? "");
            return;
        }

        var lines = new List<EventLine>();
        foreach (var e in item.Result.Entries)
        {
            if (!RightFilterAccepts(e))
            {
                continue;
            }

            var sev = EventCatalog.SeverityOf(e.Entry.EventType);
            lines.Add(new EventLine(
                e.LineNumber.ToString(CultureInfo.InvariantCulture),
                FormatTime(e.Entry.Timestamp),
                EventCatalog.Label(e.Entry.EventType),
                e.Entry.EventData ?? "",
                e.Valid ? Lang.T("chainCellOk") : Lang.T("chainCellBad"),
                (e.Valid ? EventCatalog.RowBg(sev) : AppTheme.RedBg).ToBrush(),
                EventCatalog.RowText(sev).ToBrush(),
                (e.Valid ? AppTheme.GreenText : AppTheme.RedText).ToBrush(),
                !e.Valid));
        }

        _eventsGrid.ItemsSource = lines;

        var integrity = item.Tampered
            ? string.Format(Lang.T("chainBroken"), item.Result.FirstBrokenLine)
            : Lang.T("chainIntact");
        _rightHeader.Foreground = item.Tampered ? Palette.RedText : Palette.Text;
        _rightHeader.Text = string.Format(Lang.T("hdrSelected"), item.Label, lines.Count) + "  ·  " + integrity;
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
        _footerLabel.Foreground = _configName != null && !_configValid ? Palette.RedText : Palette.TextMuted;
    }

    private async Task ExportSummary()
    {
        if (_items.Count == 0)
        {
            await MessageBox.Show(this, Lang.T("noLogsToVerify"), Lang.T("msgTitle"));
            return;
        }

        var file = await Pickers.SaveFile(this, Lang.T("exportTitle"), "exam-log-summary.csv", "csv", ("CSV (*.csv)", new[] { "*.csv" }));
        if (file is null)
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

            File.WriteAllText(file, sb.ToString(), new UTF8Encoding(true));
            await MessageBox.Show(this, string.Format(Lang.T("exportOk"), file), Lang.T("msgTitle"));
        }
        catch (Exception ex)
        {
            await MessageBox.Show(this, string.Format(Lang.T("exportErr"), ex.Message), Lang.T("msgTitle"), MessageKind.Error);
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
        StatusTier.Ok => AppTheme.GreenText,
        StatusTier.Warning => AppTheme.AmberText,
        StatusTier.Red => AppTheme.RedText,
        StatusTier.Error => AppTheme.RedText,
        _ => AppTheme.TextMuted
    };

    private static Color TierBg(StatusTier tier) => tier switch
    {
        StatusTier.Ok => AppTheme.GreenBg,
        StatusTier.Warning => AppTheme.AmberBg,
        StatusTier.Red => AppTheme.RedBg,
        StatusTier.Error => AppTheme.RedBg,
        _ => AppTheme.InfoBg
    };
}
