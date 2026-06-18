using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ExamShared;

// ---- Messages broadcast by each student client over the LAN ----

public sealed class StatusMessage
{
    public string Kind { get; init; } = "status";
    public string User { get; init; } = "";
    public string Machine { get; init; } = "";
    public string State { get; init; } = "Idle"; // Idle / Green / Yellow / Red
    public string StatusText { get; init; } = "";
    public int LogCount { get; init; }
    public string Timestamp { get; init; } = "";
}

public sealed class LogChunkMessage
{
    public string Kind { get; init; } = "log";
    public string User { get; init; } = "";
    public string Machine { get; init; } = "";
    public LogEntry[] Entries { get; init; } = Array.Empty<LogEntry>();
}

public static class MonitorProtocol
{
    public const int UdpPort = 48710;
    public const int MaxEntriesPerChunk = 5;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public static byte[] Serialize(object message) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message, message.GetType(), Options));

    public static string? KindOf(byte[] data)
    {
        try
        {
            using var doc = JsonDocument.Parse(data);
            return doc.RootElement.TryGetProperty("kind", out var k) ? k.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    public static T? Deserialize<T>(byte[] data)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(data), Options);
        }
        catch
        {
            return default;
        }
    }
}

/// <summary>Client side: send-only UDP broadcaster (no inbound socket on the student PC).</summary>
public sealed class MonitorBroadcaster : IDisposable
{
    private readonly UdpClient _udp;
    private readonly IPEndPoint[] _broadcasts;

    public MonitorBroadcaster(IEnumerable<string>? targets = null)
    {
        _udp = new UdpClient { EnableBroadcast = true };
        _broadcasts = GetBroadcastEndpoints(targets);
    }

    public void Send(object message)
    {
        try
        {
            var bytes = MonitorProtocol.Serialize(message);
            foreach (var endpoint in _broadcasts)
            {
                _udp.Send(bytes, bytes.Length, endpoint);
            }
        }
        catch
        {
            // No network (e.g. Wi-Fi disabled during the exam): silently skip; it will
            // succeed once the student restores the connection.
        }
    }

    public void Dispose() => _udp.Dispose();

    private static IPEndPoint[] GetBroadcastEndpoints(IEnumerable<string>? targets)
    {
        var endpoints = new List<IPEndPoint>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        AddEndpoint(IPAddress.Broadcast);
        AddTargets(targets);

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            var properties = nic.GetIPProperties();
            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork ||
                    IPAddress.IsLoopback(unicast.Address) ||
                    IsApipa(unicast.Address))
                {
                    continue;
                }

                var broadcast = TryGetDirectedBroadcast(unicast);
                if (broadcast is not null)
                {
                    AddEndpoint(broadcast);
                }
            }
        }

        return endpoints.ToArray();

        void AddEndpoint(IPAddress address)
        {
            var key = address.ToString();
            if (seen.Add(key))
            {
                endpoints.Add(new IPEndPoint(address, MonitorProtocol.UdpPort));
            }
        }

        void AddTargets(IEnumerable<string>? rawTargets)
        {
            if (rawTargets is null)
            {
                return;
            }

            foreach (var target in rawTargets)
            {
                if (IPAddress.TryParse(target.Trim(), out var address) &&
                    address.AddressFamily == AddressFamily.InterNetwork)
                {
                    AddEndpoint(address);
                }
            }
        }
    }

    private static IPAddress? TryGetDirectedBroadcast(UnicastIPAddressInformation unicast)
    {
        try
        {
            var mask = unicast.IPv4Mask;
            if (mask is null)
            {
                return null;
            }

            var addressBytes = unicast.Address.GetAddressBytes();
            var maskBytes = mask.GetAddressBytes();
            if (addressBytes.Length != 4 || maskBytes.Length != 4)
            {
                return null;
            }

            var broadcastBytes = new byte[4];
            for (var i = 0; i < broadcastBytes.Length; i++)
            {
                broadcastBytes[i] = (byte)(addressBytes[i] | ~maskBytes[i]);
            }

            var broadcast = new IPAddress(broadcastBytes);
            return broadcast.Equals(unicast.Address) ? null : broadcast;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsApipa(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
    }
}

/// <summary>Teacher side: listens for client broadcasts and raises events.</summary>
public sealed class MonitorListener : IDisposable
{
    private readonly UdpClient _udp;
    private volatile bool _running;

    public event Action<StatusMessage>? StatusReceived;
    public event Action<LogChunkMessage>? LogReceived;

    public MonitorListener()
    {
        _udp = new UdpClient { ExclusiveAddressUse = false };
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, MonitorProtocol.UdpPort));
    }

    public void Start()
    {
        if (_running)
        {
            return;
        }

        _running = true;
        _ = ReceiveLoopAsync();
    }

    private async Task ReceiveLoopAsync()
    {
        while (_running)
        {
            try
            {
                var result = await _udp.ReceiveAsync();
                var kind = MonitorProtocol.KindOf(result.Buffer);
                if (kind == "status")
                {
                    var msg = MonitorProtocol.Deserialize<StatusMessage>(result.Buffer);
                    if (msg is not null)
                    {
                        StatusReceived?.Invoke(msg);
                    }
                }
                else if (kind == "log")
                {
                    var msg = MonitorProtocol.Deserialize<LogChunkMessage>(result.Buffer);
                    if (msg is not null)
                    {
                        LogReceived?.Invoke(msg);
                    }
                }
            }
            catch
            {
                if (!_running)
                {
                    break;
                }
            }
        }
    }

    public void Dispose()
    {
        _running = false;
        _udp.Dispose();
    }
}

/// <summary>Verifies a hash-chained log (shared by ExamLogVerifier and ExamMonitor).</summary>
public static class LogChainVerifier
{
    public static bool Verify(IReadOnlyList<LogEntry> entries, string logSecretBase64)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(logSecretBase64);
        }
        catch
        {
            return false;
        }

        var prevHmac = "GENESIS";
        foreach (var entry in entries)
        {
            var data = entry.EventData ?? string.Empty;
            var payload = $"{entry.Sequence}|{entry.Timestamp}|{entry.EventType}|{data}|{prevHmac}";
            var calc = ComputeHmac(key, payload);

            if (entry.PrevHmacBase64 != prevHmac || !FixedEquals(calc, entry.HmacBase64))
            {
                return false;
            }

            prevHmac = entry.HmacBase64;
        }

        return true;
    }

    private static string ComputeHmac(byte[] key, string text)
    {
        using var hmac = new HMACSHA256(key);
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(text)));
    }

    private static bool FixedEquals(string a, string b)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(a), Convert.FromBase64String(b));
        }
        catch
        {
            return false;
        }
    }
}
