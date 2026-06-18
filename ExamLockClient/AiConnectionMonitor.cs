using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ExamLockClient;

/// <summary>
/// Polls active TCP connections and flags any whose remote endpoint resolves to a
/// host in the AI blocklist. Works even if the Wi-Fi driver disable failed, acting
/// as the safety net ("doble check") the teacher asked for.
/// </summary>
public sealed class AiConnectionMonitor : IDisposable
{
    private readonly string[] _blocklist;
    private readonly HashSet<string> _literalIps = new();
    private readonly HashSet<IPAddress> _resolvedIps = new();
    private readonly object _gate = new();
    private System.Timers.Timer? _pollTimer;
    private System.Timers.Timer? _resolveTimer;

    /// <summary>Raised (on a background thread) with the matching endpoint and process evidence.</summary>
    public event Action<AiConnectionEvidence>? AiConnectionDetected;

    public AiConnectionMonitor(IEnumerable<string> blocklist)
    {
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
                // Offline or unresolved domains are simply skipped this round.
            }
        }
    }

    private void Poll()
    {
        try
        {
            if (TcpConnectionOwnerTable.TryGetAll(out var ownedConnections))
            {
                foreach (var conn in ownedConnections)
                {
                    if (conn.State != TcpState.Established &&
                        conn.State != TcpState.SynSent)
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

                return;
            }

            PollWithoutOwnerPid();
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

    private string DescribeMatch(IPAddress remote)
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

    private void PollWithoutOwnerPid()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        foreach (var conn in properties.GetActiveTcpConnections())
        {
            if (conn.State != TcpState.Established &&
                conn.State != TcpState.SynSent)
            {
                continue;
            }

            var remote = conn.RemoteEndPoint.Address;
            if (Matches(remote))
            {
                AiConnectionDetected?.Invoke(BuildEvidence(remote, conn.RemoteEndPoint.Port, null));
                return;
            }
        }
    }

    private AiConnectionEvidence BuildEvidence(IPAddress remote, int remotePort, int? processId)
    {
        var process = processId is int pid ? AiProcessClassifier.TryGetProcess(pid) : null;
        return new AiConnectionEvidence
        {
            Destination = DescribeMatch(remote),
            RemoteAddress = remote,
            RemotePort = remotePort,
            ProcessId = processId,
            ProcessName = process?.ProcessName,
            ProcessPath = process?.ProcessPath,
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
