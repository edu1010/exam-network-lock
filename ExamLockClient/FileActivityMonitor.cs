using System.Diagnostics;
using System.Management;
using System.Text;

namespace ExamLockClient;

/// <summary>
/// Best-effort, heuristic detection of disallowed file usage. This is a deterrent
/// (it leaves evidence in the log), not an exhaustive hook on every file "open":
///  - New processes are inspected via WMI (Win32_Process.CommandLine) for file-path
///    arguments. A path outside the work folder, or with a disallowed extension,
///    raises the shield.
///  - A FileSystemWatcher over the work folder flags files appearing there with an
///    unknown (not allowed) extension as "unknown" (yellow).
/// </summary>
public sealed class FileActivityMonitor : IDisposable
{
    // Document/file-opener apps. Inspecting only these (plus teacher-allowed apps) keeps the
    // command-line heuristic low-noise: a compiler/JVM reading its own .jar classpath is not
    // "the student opening a file" and must not raise a false alarm.
    private static readonly HashSet<string> OpenerProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "notepad.exe", "notepad++.exe", "wordpad.exe", "write.exe",
        "winword.exe", "excel.exe", "powerpnt.exe",
        "acrord32.exe", "acrobat.exe", "sumatrapdf.exe", "foxitreader.exe",
        "code.exe", "devenv.exe", "eclipse.exe", "idea64.exe", "pycharm64.exe",
        "soffice.bin", "soffice.exe", "mspaint.exe", "photos.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe",
        "vlc.exe", "wmplayer.exe", "explorer.exe"
    };

    private readonly HashSet<string> _allowedExtensions;
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

    public FileActivityMonitor(IEnumerable<string> allowedExtensions, string workFolder, bool restrictToFolder, IEnumerable<string>? allowedProcesses = null)
    {
        _allowedExtensions = new HashSet<string>(
            allowedExtensions.Select(e => e.Trim().ToLowerInvariant()).Where(e => e.Length > 0),
            StringComparer.OrdinalIgnoreCase);
        _workFolder = workFolder?.Trim() ?? string.Empty;
        _restrictToFolder = restrictToFolder;

        _inspectProcesses = new HashSet<string>(OpenerProcesses, StringComparer.OrdinalIgnoreCase);
        foreach (var p in allowedProcesses ?? Enumerable.Empty<string>())
        {
            var name = p.Trim();
            if (name.Length > 0)
            {
                _inspectProcesses.Add(name);
            }
        }

        _excludedRoots = BuildExcludedRoots();
    }

    // Per-user temp/roaming/cache locations the student's own apps churn constantly (temp
    // files, autosaves, browser caches). Files here are machine noise, not the student opening
    // a document. We deliberately exclude ONLY these user-profile paths — not ProgramData,
    // Windows or Program Files: those are not where openers read the student's files, and some
    // (ProgramData, Windows\Temp) are user-writable, so excluding them would let a stashed
    // cheat file slip past the folder/extension checks.
    private static string[] BuildExcludedRoots()
    {
        var folders = new[]
        {
            Path.GetTempPath(),
            Environment.GetEnvironmentVariable("TEMP") ?? "",
            Environment.GetEnvironmentVariable("TMP") ?? "",
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), // AppData\Local (incl. Temp, caches)
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),      // AppData\Roaming
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
        foreach (var p in Process.GetProcesses())
        {
            _knownPids.Add(p.Id);
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

        if (_allowedExtensions.Count > 0 && !_allowedExtensions.Contains(ext))
        {
            UnknownFileDetected?.Invoke(Path.GetFileName(fullPath));
        }
    }

    private void PollCommandLines()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine FROM Win32_Process");
            using var results = searcher.Get();

            foreach (var obj in results)
            {
                var pid = SafeInt(obj["ProcessId"]);
                lock (_gate)
                {
                    if (pid == 0 || !_knownPids.Add(pid))
                    {
                        continue;
                    }
                }

                // Only inspect document-opener apps (or teacher-allowed apps); ignore the rest
                // to avoid false alarms from system processes and compiler/JVM classpaths.
                var name = obj["Name"] as string;
                if (name is null || !_inspectProcesses.Contains(name))
                {
                    continue;
                }

                var commandLine = obj["CommandLine"] as string;
                if (string.IsNullOrWhiteSpace(commandLine))
                {
                    continue;
                }

                InspectCommandLine(commandLine);
            }
        }
        catch
        {
            // WMI can be unavailable or throw transiently; ignore and retry next tick.
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

            // Only treat tokens that look like real, existing files the student opened.
            if (!LooksLikePath(token) || !SafeFileExists(token))
            {
                continue;
            }

            // Files inside the teacher-designated work folder are always inspected, even if
            // that folder happens to live under a temp/roaming path.
            var insideWorkFolder = _restrictToFolder && _workFolder.Length > 0 && IsInsideWorkFolder(token);

            // Ignore temp/roaming/cache locations outside the work folder: the student's own
            // apps constantly read and write there, so they are machine noise rather than the
            // student opening a disallowed file.
            if (!insideWorkFolder && IsInExcludedSystemLocation(token))
            {
                continue;
            }

            if (_restrictToFolder && _workFolder.Length > 0 && !insideWorkFolder)
            {
                OutsideFolderDetected?.Invoke(token);
                continue;
            }

            if (_allowedExtensions.Count > 0 && !_allowedExtensions.Contains(ext.ToLowerInvariant()))
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

    private static int SafeInt(object? value)
    {
        try
        {
            return Convert.ToInt32(value);
        }
        catch
        {
            return 0;
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _watcher?.Dispose();
    }
}
