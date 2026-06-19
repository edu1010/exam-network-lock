using System.Net;
using System.Net.NetworkInformation;

namespace ExamLockClient.Core.Platform;

/// <summary>A single active TCP connection plus the owning process id (0 when unknown).</summary>
public sealed record TcpConnectionInfo(IPAddress RemoteAddress, int RemotePort, TcpState State, int ProcessId);

/// <summary>
/// A process as seen by the platform. <see cref="Name"/> is the bare executable name without an
/// extension (e.g. "chrome", "code", "qemu-system-x86_64"), lower-cased, so the classifier matches
/// identically on Windows ("chrome.exe") and Linux ("chrome").
/// </summary>
public sealed record ProcessInfo(int Pid, string Name, string? Path, string? CommandLine)
{
    public string Summary
    {
        get
        {
            var s = Name;
            if (!string.IsNullOrWhiteSpace(Path)) s += " | " + Path;
            if (!string.IsNullOrWhiteSpace(CommandLine))
            {
                var cmd = CommandLine!.Length <= 300 ? CommandLine : CommandLine[..300] + "...";
                s += " | cmd: " + cmd;
            }

            return s;
        }
    }
}

/// <summary>
/// Everything the lock client needs from the operating system. One implementation per OS
/// (<see cref="WindowsPlatform"/>, <see cref="LinuxPlatform"/>) keeps the monitoring code portable:
/// the monitors talk only to this interface, never to netsh/WMI/iphlpapi or /proc/nmcli/rfkill.
/// </summary>
public interface IPlatform
{
    string Name { get; }

    // ---- Privilege ----
    bool IsElevated { get; }
    bool TryRelaunchElevated(string executablePath, IReadOnlyList<string> args);

    // ---- Radios (best-effort; the AI shield is the safety net) ----
    bool DisableWifi(out string error);
    bool EnableWifi(out string error);
    Task<(bool ok, string error)> SetBluetoothAsync(bool on);

    // ---- Network introspection ----
    /// <summary>Active TCP connections with the owning pid when the OS exposes it.</summary>
    bool TryGetTcpConnections(out List<TcpConnectionInfo> connections);

    /// <summary>Resolved hostnames from the OS DNS cache. Empty when the OS has no enumerable cache.</summary>
    IEnumerable<string> GetDnsCacheHosts();

    // ---- Process introspection ----
    /// <summary>Cheap snapshot: pid + bare name only.</summary>
    IReadOnlyList<ProcessInfo> GetProcessList();

    /// <summary>Full detail for one pid: name + path + command line (best-effort).</summary>
    ProcessInfo? TryGetProcess(int pid);

    // ---- Audio ----
    bool TrySetVolume(int percent);
    void Beep(int frequencyHz, int durationMs);
}
