using Microsoft.Data.Sqlite;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Reads the browser history of the current user (Chromium-family and Firefox profiles) and reports
/// visits to AI sites made after the shield started. Unlike <see cref="AiConnectionMonitor"/> it sees
/// the real hostname, so it catches sites served from shared IPs (Google) or reached over QUIC.
/// The live databases are locked by the browser, so each changed one is copied to a private
/// temporary folder and read there.
///
/// Privacy: only visits after start whose host matches the AI blocklist ever leave this class; the
/// rest of the history is never logged or sent. Private/incognito windows keep no history and are
/// not seen.
/// </summary>
public sealed class BrowserHistoryMonitor : IDisposable
{
    private const int MaxUrlLength = 300;

    private enum Kind { Chromium, Firefox }

    private sealed record HistoryDb(string Path, Kind Kind);

    private static readonly DateTime ChromiumEpoch = new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private readonly string[] _blocklist;
    private readonly DateTime _startUtc = DateTime.UtcNow;
    private readonly Dictionary<string, DateTime> _lastChange = new();
    private readonly Dictionary<string, long> _cursor = new();
    private DirectoryInfo? _temp;
    private System.Timers.Timer? _timer;
    private int _polling;

    /// <summary>Raised with (host, url) for each AI visit made after the shield started.</summary>
    public event Action<string, string>? AiUrlVisited;

    public BrowserHistoryMonitor(IEnumerable<string> blocklist)
    {
        _blocklist = blocklist
            .Select(b => b.Trim().ToLowerInvariant())
            .Where(b => b.Length > 0)
            .ToArray();
    }

    public void Start()
    {
        try
        {
            // Created with owner-only permissions on Unix.
            _temp = Directory.CreateTempSubdirectory("examlock-history-");
        }
        catch
        {
            return;
        }

        _timer = new System.Timers.Timer(5_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Poll();
        _timer.Start();
        Poll();
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _polling, 1) == 1)
        {
            return;
        }

        try
        {
            foreach (var db in FindDatabases())
            {
                try
                {
                    Scan(db);
                }
                catch
                {
                    // Locked mid-copy, schema change, unreadable profile: retried next tick.
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _polling, 0);
        }
    }

    private void Scan(HistoryDb db)
    {
        var changed = new[] { db.Path, db.Path + "-wal", db.Path + "-journal" }
            .Where(File.Exists)
            .Max(File.GetLastWriteTimeUtc);
        if (_lastChange.TryGetValue(db.Path, out var seen) && seen == changed)
        {
            return;
        }

        if (!_cursor.TryGetValue(db.Path, out var cursor))
        {
            cursor = db.Kind == Kind.Chromium
                ? (_startUtc - ChromiumEpoch).Ticks / 10
                : (_startUtc - DateTime.UnixEpoch).Ticks / 10;
        }

        var copy = Path.Combine(_temp!.FullName, "history.sqlite");
        try
        {
            File.Copy(db.Path, copy, overwrite: true);
            foreach (var suffix in new[] { "-wal", "-journal" })
            {
                // Recent visits may still sit in the WAL/journal; SQLite applies it when opening the copy.
                if (File.Exists(db.Path + suffix))
                {
                    File.Copy(db.Path + suffix, copy + suffix, overwrite: true);
                }
                else
                {
                    File.Delete(copy + suffix);
                }
            }

            using (var connection = new SqliteConnection($"Data Source={copy};Pooling=False"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = db.Kind == Kind.Chromium
                    ? "SELECT u.url, v.visit_time FROM visits v JOIN urls u ON u.id = v.url WHERE v.visit_time > $t ORDER BY v.visit_time"
                    : "SELECT p.url, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id WHERE v.visit_date > $t ORDER BY v.visit_date";
                command.Parameters.AddWithValue("$t", cursor);

                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    cursor = Math.Max(cursor, reader.GetInt64(1));
                    var url = reader.IsDBNull(0) ? "" : reader.GetString(0);
                    var host = MatchHost(url);
                    if (host is not null)
                    {
                        AiUrlVisited?.Invoke(host, url.Length > MaxUrlLength ? url[..MaxUrlLength] + "…" : url);
                    }
                }
            }

            _cursor[db.Path] = cursor;
            _lastChange[db.Path] = changed;
        }
        finally
        {
            foreach (var file in new[] { copy, copy + "-wal", copy + "-journal", copy + "-shm" })
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                    // Best effort; the folder is removed on dispose.
                }
            }
        }
    }

    private string? MatchHost(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Host.Length == 0)
        {
            return null;
        }

        var host = uri.Host.TrimEnd('.').ToLowerInvariant();
        foreach (var token in _blocklist)
        {
            if (host == token || host.EndsWith("." + token, StringComparison.Ordinal))
            {
                return host;
            }
        }

        return null;
    }

    // ----- Profile discovery -----

    private static IEnumerable<HistoryDb> FindDatabases()
    {
        foreach (var root in ChromiumRoots())
        {
            // Profiles are "Default", "Profile 1"…; Opera keeps its history in the root itself.
            foreach (var dir in WithSubdirectories(root))
            {
                var path = Path.Combine(dir, "History");
                if (File.Exists(path))
                {
                    yield return new HistoryDb(path, Kind.Chromium);
                }
            }
        }

        foreach (var root in FirefoxRoots())
        {
            foreach (var dir in WithSubdirectories(root))
            {
                var path = Path.Combine(dir, "places.sqlite");
                if (File.Exists(path))
                {
                    yield return new HistoryDb(path, Kind.Firefox);
                }
            }
        }
    }

    private static IEnumerable<string> WithSubdirectories(string root)
    {
        if (!Directory.Exists(root))
        {
            return Array.Empty<string>();
        }

        try
        {
            return Directory.EnumerateDirectories(root).Prepend(root).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string Folder(Environment.SpecialFolder folder) =>
        Environment.GetFolderPath(folder, Environment.SpecialFolderOption.DoNotVerify);

    private static IEnumerable<string> ChromiumRoots()
    {
        if (OperatingSystem.IsWindows())
        {
            var local = Folder(Environment.SpecialFolder.LocalApplicationData);
            var roaming = Folder(Environment.SpecialFolder.ApplicationData);
            return new[]
            {
                Path.Combine(local, "Google", "Chrome", "User Data"),
                Path.Combine(local, "Google", "Chrome Beta", "User Data"),
                Path.Combine(local, "Chromium", "User Data"),
                Path.Combine(local, "Microsoft", "Edge", "User Data"),
                Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"),
                Path.Combine(local, "Vivaldi", "User Data"),
                Path.Combine(roaming, "Opera Software", "Opera Stable"),
                Path.Combine(roaming, "Opera Software", "Opera GX Stable")
            };
        }

        var home = Folder(Environment.SpecialFolder.UserProfile);
        var config = Folder(Environment.SpecialFolder.ApplicationData); // $XDG_CONFIG_HOME or ~/.config
        return new[]
        {
            Path.Combine(config, "google-chrome"),
            Path.Combine(config, "google-chrome-beta"),
            Path.Combine(config, "google-chrome-unstable"),
            Path.Combine(config, "chromium"),
            Path.Combine(config, "microsoft-edge"),
            Path.Combine(config, "microsoft-edge-beta"),
            Path.Combine(config, "BraveSoftware", "Brave-Browser"),
            Path.Combine(config, "vivaldi"),
            Path.Combine(config, "opera"),
            // Snap and Flatpak keep their profiles elsewhere.
            Path.Combine(home, "snap", "chromium", "common", "chromium"),
            Path.Combine(home, ".var", "app", "com.google.Chrome", "config", "google-chrome"),
            Path.Combine(home, ".var", "app", "org.chromium.Chromium", "config", "chromium"),
            Path.Combine(home, ".var", "app", "com.microsoft.Edge", "config", "microsoft-edge"),
            Path.Combine(home, ".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser")
        };
    }

    private static IEnumerable<string> FirefoxRoots()
    {
        if (OperatingSystem.IsWindows())
        {
            var roaming = Folder(Environment.SpecialFolder.ApplicationData);
            return new[]
            {
                Path.Combine(roaming, "Mozilla", "Firefox", "Profiles"),
                Path.Combine(roaming, "librewolf", "Profiles")
            };
        }

        var home = Folder(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Path.Combine(home, ".mozilla", "firefox"),
            Path.Combine(home, ".librewolf"),
            Path.Combine(home, "snap", "firefox", "common", ".mozilla", "firefox"),
            Path.Combine(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
            Path.Combine(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf")
        };
    }

    public void Dispose()
    {
        _timer?.Dispose();
        try
        {
            _temp?.Delete(recursive: true);
        }
        catch
        {
            // Temp folder still in use by a final poll; the OS cleans /tmp eventually.
        }
    }
}
