using System.Net;
using System.Net.NetworkInformation;
using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Polls active TCP connections and flags any whose remote endpoint resolves to a host in the AI
/// blocklist. Works even if the Wi-Fi disable failed, acting as the safety net. The connection
/// table and process attribution come from <see cref="IPlatform"/>, so it behaves the same on
/// Windows (IP Helper) and Linux (/proc/net/tcp).
/// </summary>
public sealed class AiConnectionMonitor : IDisposable
{
    private readonly IPlatform _platform;
    private readonly string[] _blocklist;
    private readonly HashSet<string> _literalIps = new();
    private readonly HashSet<IPAddress> _resolvedIps = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _pollTimer;
    private System.Timers.Timer? _resolveTimer;

    public event Action<AiConnectionEvidence>? AiConnectionDetected;

    public AiConnectionMonitor(IPlatform platform, IEnumerable<string> blocklist)
    {
        _platform = platform;
        _blocklist = blocklist
            .Select(b => b.Trim().ToLowerInvariant())
            .Where(b => b.Length > 0)
            .ToArray();

        foreach (var entry in _blocklist)
        {
            if (IPAddress.TryParse(entry, out var ip))
            {
                _literalIps.Add(ip.ToString());
            }
        }
    }

    public void Start()
    {
        ResolveBlocklist();

        _resolveTimer = new System.Timers.Timer(60_000) { AutoReset = true };
        _resolveTimer.Elapsed += (_, _) => ResolveBlocklist();
        _resolveTimer.Start();

        _pollTimer = new System.Timers.Timer(2_500) { AutoReset = true };
        _pollTimer.Elapsed += (_, _) => Poll();
        _pollTimer.Start();
    }

    private void ResolveBlocklist()
    {
        foreach (var entry in _blocklist)
        {
            if (IPAddress.TryParse(entry, out _))
            {
                continue;
            }

            try
            {
                foreach (var addr in Dns.GetHostAddresses(entry))
                {
                    lock (_gate)
                    {
                        _resolvedIps.Add(addr);
                    }
                }
            }
            catch
            {
                // Offline or unresolved domains are skipped this round.
            }
        }
    }

    private void Poll()
    {
        try
        {
            if (!_platform.TryGetTcpConnections(out var connections))
            {
                return;
            }

            foreach (var conn in connections)
            {
                if (conn.State != TcpState.Established && conn.State != TcpState.SynSent)
                {
                    continue;
                }

                if (Matches(conn.RemoteAddress))
                {
                    AiConnectionDetected?.Invoke(BuildEvidence(
                        conn.RemoteAddress,
                        conn.RemotePort,
                        conn.ProcessId > 0 ? conn.ProcessId : null));
                    return;
                }
            }
        }
        catch
        {
            // Transient enumeration errors are ignored; next tick retries.
        }
    }

    private bool Matches(IPAddress remote)
    {
        lock (_gate)
        {
            return _literalIps.Contains(remote.ToString()) || _resolvedIps.Contains(remote);
        }
    }

    private static string DescribeMatch(IPAddress remote)
    {
        try
        {
            var host = Dns.GetHostEntry(remote).HostName;
            return $"{host} ({remote})";
        }
        catch
        {
            return remote.ToString();
        }
    }

    private AiConnectionEvidence BuildEvidence(IPAddress remote, int remotePort, int? processId)
    {
        var process = processId is int pid ? _platform.TryGetProcess(pid) : null;
        return new AiConnectionEvidence
        {
            Destination = DescribeMatch(remote),
            RemoteAddress = remote,
            RemotePort = remotePort,
            ProcessId = processId,
            ProcessName = process?.Name,
            ProcessPath = process?.Path,
            CommandLine = process?.CommandLine,
            IsStudentFacingProcess = AiProcessClassifier.IsStudentFacing(process)
        };
    }

    public void Dispose()
    {
        _pollTimer?.Dispose();
        _resolveTimer?.Dispose();
    }
}
