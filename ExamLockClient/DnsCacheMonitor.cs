using System.Management;

namespace ExamLockClient;

/// <summary>
/// Reads the Windows DNS resolver cache and flags any resolved hostname that matches the AI
/// blocklist. This catches API/CLI subdomains (e.g. api.anthropic.com used by Claude Code,
/// api.openai.com used by Codex, api.githubcopilot.com used by Copilot) and even connections
/// that have already closed — cases the live-TCP monitor can miss.
/// </summary>
public sealed class DnsCacheMonitor : IDisposable
{
    private readonly string[] _blocklist;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private System.Timers.Timer? _timer;

    /// <summary>Raised (background thread) with the matching hostname.</summary>
    public event Action<string>? AiHostnameResolved;

    public DnsCacheMonitor(IEnumerable<string> blocklist)
    {
        _blocklist = blocklist
            .Select(b => b.Trim().ToLowerInvariant())
            .Where(b => b.Length > 0)
            .ToArray();
    }

    public void Start()
    {
        // Ignore DNS entries that were already cached before the exam shield started.
        // They may come from browser preload, Windows background services, or earlier activity.
        Poll(raiseEvents: false);

        _timer = new System.Timers.Timer(3_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Poll(raiseEvents: true);
        _timer.Start();
    }

    private void Poll(bool raiseEvents)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\StandardCimv2",
                "SELECT Entry, Name, Data FROM MSFT_DNSClientCache");
            using var results = searcher.Get();

            foreach (var obj in results)
            {
                Check(obj["Entry"] as string, raiseEvents);
                Check(obj["Name"] as string, raiseEvents);
                Check(obj["Data"] as string, raiseEvents);
            }
        }
        catch
        {
            // WMI/DNS cache may be unavailable; ignore and retry next tick.
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
            // Exact host or any subdomain of the blocked domain.
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
