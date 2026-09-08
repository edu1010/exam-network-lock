using ExamShared;
using System.Diagnostics;

namespace ExamLockClient;

/// <summary>
/// Snapshots the processes running when the lockdown starts, then flags explicitly blocked programs (including at startup) or any NEW
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

    private readonly ProcessPolicy _policy;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _timer;

    public event Action<string>? UnknownProcessStarted;
    public event Action<string>? BlockedProcessDetected;

    public ProcessMonitor(IEnumerable<string> allowedProcesses, IEnumerable<string>? blockedProcesses = null)
    {
        _policy = new ProcessPolicy(allowedProcesses, blockedProcesses, SafeBaseProcesses);
    }

    public void Start()
    {
        // Existing apps form the allow-list baseline, but explicit prohibitions apply immediately.
        Poll(reportUnknown: false);
        _timer = new System.Timers.Timer(2_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Poll();
        _timer.Start();
    }

    private void Poll(bool reportUnknown = true)
    {
        lock (_gate)
        {
            try
            {
                var snapshot = Snapshot();
                // Forget exited processes so a recycled PID is not exempted forever.
                _knownPids.IntersectWith(snapshot.Select(p => p.Pid));
                foreach (var process in snapshot)
                {
                    if (!_knownPids.Add(process.Pid)) continue;
                    switch (_policy.Evaluate(process.Name, alreadyRunning: !reportUnknown))
                    {
                        case ProcessDecision.Blocked:
                            BlockedProcessDetected?.Invoke(process.Name);
                            break;
                        case ProcessDecision.Unknown:
                            UnknownProcessStarted?.Invoke(process.Name);
                            break;
                    }
                }
            }
            catch
            {
                // Transient enumeration errors are retried on the next tick.
            }
        }
    }

    private static (int Pid, string Name)[] Snapshot()
    {
        var snapshot = new List<(int Pid, string Name)>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { snapshot.Add((process.Id, process.ProcessName + ".exe")); }
                catch { /* Process exited or is inaccessible; do not invent an unknown program. */ }
            }
        }
        return snapshot.ToArray();
    }

    public void Dispose() => _timer?.Dispose();
}
