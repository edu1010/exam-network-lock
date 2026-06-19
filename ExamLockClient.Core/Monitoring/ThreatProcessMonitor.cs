using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Flags two kinds of bypass attempts by process (deterrent only, never kills):
///  - Dedicated AI desktop/IDE tools and CLI agents (Cursor, Windsurf, ChatGPT/Claude apps, local
///    LLMs; CLI agents like Codex/Claude Code are spotted via their command line under node/python).
///  - Virtual machines / hypervisors (VirtualBox, VMware, QEMU, GNOME Boxes…), a common way to
///    escape the lock.
/// </summary>
public sealed class ThreatProcessMonitor : IDisposable
{
    private static readonly HashSet<string> VmProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "vboxheadless", "virtualbox", "virtualboxvm", "vboxsvc",
        "vmware", "vmware-vmx", "vmware-tray", "vmplayer", "vmwp",
        "qemu", "qemu-system-x86_64", "qemu-system-i386", "qemu-system-aarch64",
        "gnome-boxes", "virt-manager", "libvirtd"
    };

    private readonly IPlatform _platform;
    private readonly bool _detectAiTools;
    private readonly bool _detectVms;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _timer;

    public event Action<string>? AiToolDetected;
    public event Action<string>? VmDetected;

    public ThreatProcessMonitor(IPlatform platform, bool detectAiTools, bool detectVms)
    {
        _platform = platform;
        _detectAiTools = detectAiTools;
        _detectVms = detectVms;
    }

    public void Start()
    {
        foreach (var p in _platform.GetProcessList())
        {
            _knownPids.Add(p.Pid);
        }

        _timer = new System.Timers.Timer(2_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Poll();
        _timer.Start();
    }

    private void Poll()
    {
        try
        {
            foreach (var p in _platform.GetProcessList())
            {
                lock (_gate)
                {
                    if (!_knownPids.Add(p.Pid))
                    {
                        continue;
                    }
                }

                // Fetch full detail (path + command line) only for genuinely new pids.
                var detail = _platform.TryGetProcess(p.Pid) ?? p;
                var name = detail.Name;

                if (_detectAiTools &&
                    (AiProcessClassifier.IsDedicatedAiTool(detail) ||
                     AiProcessClassifier.IsDedicatedAiToolName(name)))
                {
                    AiToolDetected?.Invoke(detail.Summary);
                }
                else if (_detectVms && VmProcesses.Contains(name))
                {
                    VmDetected?.Invoke(name);
                }
            }
        }
        catch
        {
            // Ignore transient enumeration errors.
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}
