using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ExamLockClient.Core.Monitoring;
using ExamLockClient.Core.Platform;
using ExamShared;
using Microsoft.Data.Sqlite;

// Run with HOME and XDG_CONFIG_HOME pointing at an empty scratch folder: fake browser profiles are created there.

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
    Console.WriteLine("PASS: " + message);
}

static SqliteConnection Open(string path)
{
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    var connection = new SqliteConnection($"Data Source={path};Pooling=False");
    connection.Open();
    return connection;
}

static void Exec(SqliteConnection connection, string sql, params (string, object)[] args)
{
    using var command = connection.CreateCommand();
    command.CommandText = sql;
    foreach (var (name, value) in args) command.Parameters.AddWithValue(name, value);
    command.ExecuteNonQuery();
}

// DoNotVerify: with the default option .NET returns "" for a folder that does not exist yet.
var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
var config = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify);
Check(Path.IsPathRooted(config) && (home.Contains("scratch") || home.Contains("tmp")) && config.StartsWith(home),
    "Running against a scratch HOME, not the real profile");

long ChromeTime(DateTime utc) => (utc - new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks / 10;
long FirefoxTime(DateTime utc) => (utc - DateTime.UnixEpoch).Ticks / 10;

// Chrome profile with a visit to Gemini from BEFORE the exam.
using var chrome = Open(Path.Combine(config, "google-chrome", "Profile 1", "History"));
Exec(chrome, "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT); CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)");
Exec(chrome, "INSERT INTO urls VALUES (1, 'https://gemini.google.com/app/old'); INSERT INTO visits (url, visit_time) VALUES (1, $t)",
    ("$t", ChromeTime(DateTime.UtcNow.AddMinutes(-5))));

// Snap Firefox profile in WAL mode, kept open like a running browser.
using var firefox = Open(Path.Combine(home, "snap", "firefox", "common", ".mozilla", "firefox", "abc.default", "places.sqlite"));
Exec(firefox, "PRAGMA journal_mode=WAL; CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT); CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)");

var hits = new ConcurrentQueue<(string Host, string Url)>();
using var monitor = new BrowserHistoryMonitor(ConfigDefaults.DefaultAiBlocklist);
monitor.AiUrlVisited += (host, url) => hits.Enqueue((host, url));
monitor.Start();
await Task.Delay(500);
Check(hits.IsEmpty, "Visits from before the exam are ignored");

Exec(chrome, "INSERT INTO urls VALUES (2, 'https://www.wikipedia.org/wiki/Java'); INSERT INTO visits (url, visit_time) VALUES (2, $t)", ("$t", ChromeTime(DateTime.UtcNow)));
Exec(chrome, "INSERT INTO urls VALUES (3, 'https://aistudio.google.com/prompts/new_chat'); INSERT INTO visits (url, visit_time) VALUES (3, $t)", ("$t", ChromeTime(DateTime.UtcNow)));
Exec(firefox, "INSERT INTO moz_places VALUES (1, 'https://gemini.google.com/app/abc123'); INSERT INTO moz_historyvisits (place_id, visit_date) VALUES (1, $t)", ("$t", FirefoxTime(DateTime.UtcNow)));
Check(File.Exists(Path.Combine(home, "snap", "firefox", "common", ".mozilla", "firefox", "abc.default", "places.sqlite-wal")), "Firefox visit still only in the WAL");

await Task.Delay(6_500);
var found = hits.ToArray();
Check(found.Any(h => h.Host == "aistudio.google.com" && h.Url.Contains("new_chat")), "Chrome visit to AI Studio after start reported");
Check(found.Any(h => h.Host == "gemini.google.com" && h.Url.EndsWith("abc123")), "Firefox (snap, WAL) visit to Gemini after start reported");
Check(!found.Any(h => h.Url.Contains("wikipedia")), "Non-AI visits are never reported");
Check(found.Length == 2, "Each visit reported once");

await Task.Delay(5_500);
Check(hits.Count == 2, "Unchanged history is not reported again");

// QUIC: a connected UDP socket must show up with its remote address.
if (OperatingSystem.IsLinux())
{
    using var udp = new UdpClient(AddressFamily.InterNetwork);
    udp.Connect(IPAddress.Parse("192.0.2.10"), 443);
    Check(new LinuxPlatform().TryGetTcpConnections(out var connections)
        && connections.Any(c => c.RemoteAddress.Equals(IPAddress.Parse("192.0.2.10")) && c.RemotePort == 443 && c.State == TcpState.Established),
        "Connected UDP (QUIC) socket listed with its remote address");
}
