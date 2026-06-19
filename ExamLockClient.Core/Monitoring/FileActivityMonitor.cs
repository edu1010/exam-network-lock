using System.Text;
using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Best-effort, heuristic detection of disallowed file usage (a deterrent that leaves evidence in
/// the log, not an exhaustive hook on every open):
///  - New document-opener processes have their command line inspected for file-path arguments. A
///    path outside the work folder, or with a disallowed extension, raises the shield.
///  - A FileSystemWatcher over the work folder flags files with an unknown extension as "unknown".
/// Command lines come from <see cref="IPlatform"/> (WMI on Windows, /proc on Linux) so it works on
/// both. Path detection accepts Windows and POSIX shapes.
/// </summary>
public sealed class FileActivityMonitor : IDisposable
{
    // Document/file-opener apps (bare names). Inspecting only these plus teacher-allowed apps keeps
    // the heuristic low-noise: a compiler/JVM reading its own classpath is not "the student opening
    // a file".
    private static readonly HashSet<string> OpenerProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "notepad", "notepad++", "wordpad", "write", "winword", "excel", "powerpnt",
        "acrord32", "acrobat", "sumatrapdf", "foxitreader", "code", "devenv", "eclipse",
        "idea", "pycharm", "soffice", "mspaint", "photos", "wmplayer", "explorer",
        "chrome", "google-chrome", "chromium", "msedge", "firefox", "iexplore", "opera", "brave",
        "vlc", "mpv", "totem",
        // Linux openers.
        "gedit", "kate", "kwrite", "gnome-text-editor", "libreoffice", "lowriter", "localc",
        "loimpress", "evince", "okular", "xpdf", "mupdf", "zathura", "eog", "gwenview", "gimp",
        "nautilus", "dolphin", "nemo", "thunar", "xdg-open"
    };

    private readonly IPlatform _platform;
    private readonly HashSet<string> _allowedExtensions;
    private readonly HashSet<string> _blockedExtensions;
    private readonly HashSet<string> _inspectProcesses;
    private readonly string _workFolder;
    private readonly bool _restrictToFolder;
    private readonly string[] _excludedRoots;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _gate = new();

    private System.Timers.Timer? _timer;
    private FileSystemWatcher? _watcher;

    public event Action<string>? ForbiddenFileDetected;   // red
    public event Action<string>? OutsideFolderDetected;   // red
    public event Action<string>? UnknownFileDetected;     // yellow

    public FileActivityMonitor(
        IPlatform platform,
        IEnumerable<string> allowedExtensions,
        string workFolder,
        bool restrictToFolder,
        IEnumerable<string>? allowedProcesses = null,
        IEnumerable<string>? blockedExtensions = null)
    {
        _platform = platform;
        _allowedExtensions = new HashSet<string>(
            allowedExtensions.Select(e => e.Trim().ToLowerInvariant()).Where(e => e.Length > 0),
            StringComparer.OrdinalIgnoreCase);
        _blockedExtensions = _allowedExtensions.Count > 0
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(
                (blockedExtensions ?? Enumerable.Empty<string>())
                    .Select(e => e.Trim().ToLowerInvariant()).Where(e => e.Length > 0),
                StringComparer.OrdinalIgnoreCase);
        _workFolder = workFolder?.Trim() ?? string.Empty;
        _restrictToFolder = restrictToFolder;

        _inspectProcesses = new HashSet<string>(OpenerProcesses, StringComparer.OrdinalIgnoreCase);
        foreach (var p in allowedProcesses ?? Enumerable.Empty<string>())
        {
            var name = ProcessNames.Bare(p);
            if (name.Length > 0)
            {
                _inspectProcesses.Add(name);
            }
        }

        _excludedRoots = BuildExcludedRoots();
    }

    // Per-user temp/cache/config locations the student's own apps churn constantly. Files here are
    // machine noise, not the student opening a document. We exclude ONLY these user-profile paths.
    private static string[] BuildExcludedRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var folders = new[]
        {
            Path.GetTempPath(),
            Environment.GetEnvironmentVariable("TEMP") ?? "",
            Environment.GetEnvironmentVariable("TMP") ?? "",
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), // Win AppData\Local, Linux ~/.local/share
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),      // Win AppData\Roaming, Linux ~/.config
            string.IsNullOrEmpty(home) ? "" : Path.Combine(home, ".cache"),
        };

        return folders
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(NormalizeRoot)
            .Where(f => f.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string NormalizeRoot(string path)
    {
        try
        {
            return Path.GetFullPath(path)
                       .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                   + Path.DirectorySeparatorChar;
        }
        catch
        {
            return string.Empty;
        }
    }

    private bool IsInExcludedSystemLocation(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            foreach (var root in _excludedRoots)
            {
                if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // If we cannot resolve it, do not treat it as excluded.
        }

        return false;
    }

    public void Start()
    {
        foreach (var p in _platform.GetProcessList())
        {
            _knownPids.Add(p.Pid);
        }

        _timer = new System.Timers.Timer(2_500) { AutoReset = true };
        _timer.Elapsed += (_, _) => PollCommandLines();
        _timer.Start();

        StartWatcher();
    }

    private void StartWatcher()
    {
        if (_workFolder.Length == 0 || !Directory.Exists(_workFolder))
        {
            return;
        }

        try
        {
            _watcher = new FileSystemWatcher(_workFolder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            _watcher.Created += (_, e) => InspectWatchedFile(e.FullPath);
            _watcher.Renamed += (_, e) => InspectWatchedFile(e.FullPath);
        }
        catch
        {
            // Watcher is optional; ignore failures.
        }
    }

    private void InspectWatchedFile(string fullPath)
    {
        var ext = Path.GetExtension(fullPath).ToLowerInvariant();
        if (ext.Length == 0)
        {
            return;
        }

        if (_blockedExtensions.Contains(ext))
        {
            ForbiddenFileDetected?.Invoke(Path.GetFileName(fullPath));
            return;
        }

        if (_allowedExtensions.Count > 0 && !_allowedExtensions.Contains(ext))
        {
            UnknownFileDetected?.Invoke(Path.GetFileName(fullPath));
        }
    }

    private void PollCommandLines()
    {
        try
        {
            foreach (var process in _platform.GetProcessList())
            {
                lock (_gate)
                {
                    if (!_knownPids.Add(process.Pid))
                    {
                        continue;
                    }
                }

                // Only inspect document-opener apps (or teacher-allowed apps).
                if (!_inspectProcesses.Contains(process.Name))
                {
                    continue;
                }

                var detail = _platform.TryGetProcess(process.Pid);
                if (detail?.CommandLine is { } commandLine && !string.IsNullOrWhiteSpace(commandLine))
                {
                    InspectCommandLine(commandLine);
                }
            }
        }
        catch
        {
            // Process enumeration can throw transiently; ignore and retry next tick.
        }
    }

    private void InspectCommandLine(string commandLine)
    {
        foreach (var token in TokenizeArguments(commandLine).Skip(1))
        {
            var ext = Path.GetExtension(token);
            if (string.IsNullOrEmpty(ext))
            {
                continue;
            }

            if (!LooksLikePath(token) || !SafeFileExists(token))
            {
                continue;
            }

            var insideWorkFolder = _restrictToFolder && _workFolder.Length > 0 && IsInsideWorkFolder(token);

            if (!insideWorkFolder && IsInExcludedSystemLocation(token))
            {
                continue;
            }

            if (_restrictToFolder && _workFolder.Length > 0 && !insideWorkFolder)
            {
                OutsideFolderDetected?.Invoke(token);
                continue;
            }

            var lowerExt = ext.ToLowerInvariant();
            if (_blockedExtensions.Contains(lowerExt))
            {
                ForbiddenFileDetected?.Invoke(token);
                continue;
            }

            if (_allowedExtensions.Count > 0 && !_allowedExtensions.Contains(lowerExt))
            {
                ForbiddenFileDetected?.Invoke(token);
            }
        }
    }

    private bool IsInsideWorkFolder(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var root = Path.GetFullPath(_workFolder)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return true; // If we cannot resolve it, do not raise a false alarm.
        }
    }

    private static bool SafeFileExists(string token)
    {
        try
        {
            return File.Exists(token);
        }
        catch
        {
            return false;
        }
    }

    private static bool LooksLikePath(string token)
    {
        return token.Contains(":\\") || token.StartsWith("\\\\") ||
               token.StartsWith(".\\") || token.StartsWith("..\\") ||
               token.StartsWith('/') || token.StartsWith("./") || token.StartsWith("../") ||
               token.StartsWith("~/") ||
               token.Contains('/') || token.Contains('\\');
    }

    private static IEnumerable<string> TokenizeArguments(string commandLine)
    {
        var tokens = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;

        foreach (var c in commandLine)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (c == ' ' && !inQuotes)
            {
                if (sb.Length > 0)
                {
                    tokens.Add(sb.ToString());
                    sb.Clear();
                }
            }
            else
            {
                sb.Append(c);
            }
        }

        if (sb.Length > 0)
        {
            tokens.Add(sb.ToString());
        }

        return tokens;
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _watcher?.Dispose();
    }
}
