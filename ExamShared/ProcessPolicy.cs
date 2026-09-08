namespace ExamShared;

public enum ProcessDecision { Allowed, Unknown, Blocked }

/// <summary>Name-based, advisory rules shared by Windows and Linux. Never terminates processes.</summary>
public sealed class ProcessPolicy
{
    private readonly HashSet<string> _allowed;
    private readonly HashSet<string> _blocked;
    private readonly HashSet<string> _system;

    public ProcessPolicy(IEnumerable<string> allowed, IEnumerable<string>? blocked, IEnumerable<string> system)
    {
        _allowed = Names(allowed);
        _blocked = Names(blocked ?? Array.Empty<string>());
        _system = Names(system);
    }

    public ProcessDecision Evaluate(string? name, bool alreadyRunning)
    {
        var normalized = Normalize(name);
        if (normalized.Length == 0) return ProcessDecision.Allowed;
        // Explicit teacher rules also apply at startup and take priority over all exemptions.
        if (_blocked.Contains(normalized)) return ProcessDecision.Blocked;
        if (alreadyRunning || _system.Contains(normalized) || _allowed.Count == 0 || _allowed.Contains(normalized))
            return ProcessDecision.Allowed;
        return ProcessDecision.Unknown;
    }

    public static string Normalize(string? name)
    {
        var value = (name ?? "").Trim().Replace('\\', '/');
        value = value[(value.LastIndexOf('/') + 1)..];
        if (value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || value.EndsWith(".bin", StringComparison.OrdinalIgnoreCase))
            value = value[..^4];
        return value.ToLowerInvariant();
    }

    private static HashSet<string> Names(IEnumerable<string> values) =>
        new(values.Select(Normalize).Where(n => n.Length > 0), StringComparer.OrdinalIgnoreCase);
}
