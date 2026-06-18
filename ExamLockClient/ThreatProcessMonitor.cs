using System.Diagnostics;

namespace ExamLockClient;

/// <summary>
/// Flags two kinds of bypass attempts by process name (deterrent only, never kills):
///  - AI desktop/IDE tools (Cursor, Windsurf, the ChatGPT/Claude desktop apps, local LLMs…).
///    CLI agents like Codex or Claude Code often run under node.exe/cmd.exe/powershell.exe,
///    so their command line is inspected when Windows exposes it.
///  - Virtual machines / hypervisors (VirtualBox, VMware, Hyper-V worker, QEMU). A VM is a
///    common way to escape the lock; the host cannot see inside it, so the presence of the VM
///    itself is the signal.
/// </summary>
public sealed class ThreatProcessMonitor : IDisposable
{
    private static readonly HashSet<string> VmProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "vboxheadless.exe", "virtualbox.exe", "virtualboxvm.exe", "vboxsvc.exe",
        "vmware.exe", "vmware-vmx.exe", "vmware-tray.exe", "vmplayer.exe",
        "vmwp.exe", "qemu.exe", "qemu-system-x86_64.exe", "qemu-system-i386.exe"
    };

    private readonly bool _detectAiTools;
    private readonly bool _detectVms;
    private readonly HashSet<int> _knownPids = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _timer;

    public event Action<string>? AiToolDetected;
    public event Action<string>? VmDetected;

    public ThreatProcessMonitor(bool detectAiTools, bool detectVms)
    {
        _detectAiTools = detectAiTools;
        _detectVms = detectVms;
    }

    public void Start()
    {
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

                var evidence = AiProcessClassifier.TryGetProcess(p.Id);
                var exe = evidence?.ProcessName ?? SafeProcessName(p);

                if (_detectAiTools &&
                    (AiProcessClassifier.IsDedicatedAiTool(evidence) ||
                     AiProcessClassifier.IsDedicatedAiToolProcessName(exe)))
                {
                    AiToolDetected?.Invoke(evidence?.Summary ?? exe);
                }
                else if (_detectVms && VmProcesses.Contains(exe))
                {
                    VmDetected?.Invoke(exe);
                }
            }
        }
        catch
        {
            // Ignore transient enumeration errors.
        }
    }

    private static string SafeProcessName(Process process)
    {
        try
        {
            var name = process.ProcessName;
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
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
