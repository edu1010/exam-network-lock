using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Reads the OS DNS resolver cache and flags any resolved hostname matching the AI blocklist. This
/// catches API/CLI subdomains (api.anthropic.com, api.openai.com…) and connections that already
/// closed. On platforms with no enumerable cache (Linux) <see cref="IPlatform.GetDnsCacheHosts"/>
/// returns nothing and this monitor is a harmless no-op.
/// </summary>
public sealed class DnsCacheMonitor : IDisposable
{
    private readonly IPlatform _platform;
    private readonly string[] _blocklist;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private System.Timers.Timer? _timer;

    public event Action<string>? AiHostnameResolved;

    public DnsCacheMonitor(IPlatform platform, IEnumerable<string> blocklist)
    {
        _platform = platform;
        _blocklist = blocklist
            .Select(b => b.Trim().ToLowerInvariant())
            .Where(b => b.Length > 0)
            .ToArray();
    }

    public void Start()
    {
        // Ignore entries already cached before the shield started (browser preload, background
        // services, earlier activity).
        Poll(raiseEvents: false);

        _timer = new System.Timers.Timer(3_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Poll(raiseEvents: true);
        _timer.Start();
    }

    private void Poll(bool raiseEvents)
    {
        try
        {
            foreach (var host in _platform.GetDnsCacheHosts())
            {
                Check(host, raiseEvents);
            }
        }
        catch
        {
            // Cache unavailable; retry next tick.
        }
    }

    private void Check(string? host, bool raiseEvents)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return;
        }

        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0 || !_seen.Add(h))
        {
            return;
        }

        if (raiseEvents && IsBlocked(h))
        {
            AiHostnameResolved?.Invoke(h);
        }
    }

    private bool IsBlocked(string host)
    {
        foreach (var token in _blocklist)
        {
            if (host == token || host.EndsWith("." + token, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}
