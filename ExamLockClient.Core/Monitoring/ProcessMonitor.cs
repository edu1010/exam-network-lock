using ExamShared;
using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Snapshots the processes running when the lockdown starts, then flags explicitly blocked programs (including at startup) or any NEW process whose
/// executable is not in the allowed list (and not a known-safe OS process). Deterrent only — never
/// kills anything. Names are matched bare/lower-cased so a teacher's allow-list entry ("eclipse",
/// "code", "java") works on Windows and Linux alike.
/// </summary>
public sealed class ProcessMonitor : IDisposable
{
    // Always-present OS/shell/desktop processes that must never raise the shield. Covers Windows
    // and common Linux desktop stacks (GNOME, KDE, systemd, audio, portals).
    private static readonly HashSet<string> SafeBaseProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows.
        "explorer", "svchost", "csrss", "wininit", "winlogon", "services", "lsass", "smss",
        "fontdrvhost", "dwm", "sihost", "taskhostw", "ctfmon", "runtimebroker", "searchhost",
        "startmenuexperiencehost", "shellexperiencehost", "textinputhost", "systemsettings",
        "dllhost", "conhost", "audiodg", "spoolsv", "system", "idle", "registry",
        "memory compression", "examlockclient",

        // Linux core + desktop.
        "systemd", "systemd-journald", "systemd-logind", "systemd-resolved", "systemd-udevd",
        "systemd-oomd", "systemd-timesyncd", "init", "kthreadd", "login", "agetty", "cron", "crond",
        "rsyslogd", "dbus-daemon", "dbus-broker", "polkitd", "udisksd", "upowerd", "accounts-daemon",
        "rtkit-daemon", "networkmanager", "wpa_supplicant", "snapd", "packagekitd", "colord",
        "gnome-shell", "gnome-session", "gnome-session-binary", "gnome-keyring-daemon",
        "gdm", "gdm-session-worker", "xorg", "xwayland", "plasmashell", "kwin_x11", "kwin_wayland",
        "ksmserver", "kded5", "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber",
        "xdg-desktop-portal", "xdg-document-portal", "xdg-permission-store", "ibus-daemon",
        "ibus-x11", "at-spi-bus-launcher", "at-spi2-registryd", "tracker-miner-fs", "goa-daemon"
    };

    private readonly IPlatform _platform;
    private readonly ProcessPolicy _policy;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _timer;

    public event Action<string>? UnknownProcessStarted;
    public event Action<string>? BlockedProcessDetected;

    public ProcessMonitor(IPlatform platform, IEnumerable<string> allowedProcesses, IEnumerable<string>? blockedProcesses = null)
    {
        _platform = platform;
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

    private (int Pid, string Name)[] Snapshot() => _platform.GetProcessList().Select(p => (p.Pid, p.Name)).ToArray();

    public void Dispose() => _timer?.Dispose();
}
