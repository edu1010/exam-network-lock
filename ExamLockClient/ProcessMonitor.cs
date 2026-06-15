using System.Diagnostics;

namespace ExamLockClient;

/// <summary>
/// Snapshots the processes running when the lockdown starts, then flags any NEW
/// process whose executable is not in the allowed list (and not a known-safe OS
/// process). Deterrent only — it never kills anything.
/// </summary>
public sealed class ProcessMonitor : IDisposable
{
    // Common OS/shell processes that are always present and should not raise the shield.
    private static readonly HashSet<string> SafeBaseProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "smss.exe", "fontdrvhost.exe", "dwm.exe",
        "sihost.exe", "taskhostw.exe", "ctfmon.exe", "runtimebroker.exe",
        "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
        "textinputhost.exe", "systemsettings.exe", "dllhost.exe", "conhost.exe",
        "audiodg.exe", "spoolsv.exe", "system", "idle", "registry", "memory compression",
        "examlockclient.exe"
    };

    private readonly HashSet<string> _allowed;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _timer;

    /// <summary>Raised with the executable name of a new, non-allowed process.</summary>
    public event Action<string>? UnknownProcessStarted;

    public ProcessMonitor(IEnumerable<string> allowedProcesses)
    {
        _allowed = new HashSet<string>(
            allowedProcesses.Select(p => p.Trim()).Where(p => p.Length > 0),
            StringComparer.OrdinalIgnoreCase);
    }

    public void Start()
    {
        // Baseline: everything already running is accepted.
        foreach (var p in Process.GetProcesses())
        {
            _knownPids.Add(p.Id);
        }

        _timer = new System.Timers.Timer(2_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Poll();
        _timer.Start();
    }

    private void Poll()
    {
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                lock (_gate)
                {
                    if (!_knownPids.Add(p.Id))
                    {
                        continue;
                    }
                }

                var exe = SafeProcessName(p);
                if (IsAllowed(exe))
                {
                    continue;
                }

                UnknownProcessStarted?.Invoke(exe);
            }
        }
        catch
        {
            // Ignore transient enumeration errors.
        }
    }

    private bool IsAllowed(string exe)
    {
        if (SafeBaseProcesses.Contains(exe))
        {
            return true;
        }

        // If the teacher set no allowlist, do not flag processes by name.
        if (_allowed.Count == 0)
        {
            return true;
        }

        return _allowed.Contains(exe);
    }

    private static string SafeProcessName(Process p)
    {
        try
        {
            return p.ProcessName + ".exe";
        }
        catch
        {
            return "unknown.exe";
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}
