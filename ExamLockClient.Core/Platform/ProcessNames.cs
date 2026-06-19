namespace ExamLockClient.Core.Platform;

/// <summary>
/// Normalises an executable/process name to a bare, lower-cased token so the same blocklist matches
/// on Windows ("chrome.exe", "soffice.bin") and Linux ("chrome", "soffice"). Only known executable
/// suffixes are stripped, so version-bearing names like "python3.11" are left intact.
/// </summary>
public static class ProcessNames
{
    private static readonly string[] StrippableSuffixes = { ".exe", ".bin" };

    public static string Bare(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var name = raw.Trim();

        // Take the file name only (handles full paths from /proc/<pid>/exe or cmdline argv0).
        var slash = name.LastIndexOfAny(new[] { '/', '\\' });
        if (slash >= 0 && slash < name.Length - 1)
        {
            name = name[(slash + 1)..];
        }

        foreach (var suffix in StrippableSuffixes)
        {
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                name = name[..^suffix.Length];
                break;
            }
        }

        return name.ToLowerInvariant();
    }
}
