using System.Text;
using System.Text.Json;
using ExamShared;

namespace ExamLockClient;

/// <summary>
/// Broadcasts this student's shield state and tamper-evident log to the teacher's ExamMonitor
/// over the LAN (UDP, send-only). While the network is down (Wi-Fi disabled during the exam)
/// the broadcasts simply no-op; once the student restores the connection (password A) they
/// start arriving — so the teacher sees the full log when the student goes online to upload.
/// </summary>
public sealed class MonitorReporter : IDisposable
{
    private const int MaxEntries = 300;

    private readonly MonitorBroadcaster _broadcaster = new();
    private readonly string _user = Environment.UserName;
    private readonly string _machine = Environment.MachineName;
    private readonly string _logPath;

    private volatile string _state = "Idle";
    private volatile string _statusText = "";
    private System.Timers.Timer? _timer;

    public MonitorReporter(string logPath)
    {
        _logPath = logPath;
    }

    public void SetState(string state, string statusText)
    {
        _state = state;
        _statusText = statusText;
    }

    public void Start()
    {
        _timer = new System.Timers.Timer(3_000) { AutoReset = true };
        _timer.Elapsed += (_, _) => Tick();
        _timer.Start();
        Tick();
    }

    private void Tick()
    {
        var entries = ReadLog();

        _broadcaster.Send(new StatusMessage
        {
            User = _user,
            Machine = _machine,
            State = _state,
            StatusText = _statusText,
            LogCount = entries.Count,
            Timestamp = DateTime.Now.ToString("O")
        });

        for (var i = 0; i < entries.Count; i += MonitorProtocol.MaxEntriesPerChunk)
        {
            var chunk = entries.GetRange(i, Math.Min(MonitorProtocol.MaxEntriesPerChunk, entries.Count - i));
            _broadcaster.Send(new LogChunkMessage
            {
                User = _user,
                Machine = _machine,
                Entries = chunk.ToArray()
            });
        }
    }

    private List<LogEntry> ReadLog()
    {
        var entries = new List<LogEntry>();
        try
        {
            foreach (var line in File.ReadLines(_logPath, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var entry = JsonSerializer.Deserialize<LogEntry>(line);
                if (entry is not null)
                {
                    entries.Add(entry);
                }
            }
        }
        catch
        {
            // Log not ready yet or transiently locked; report what we have.
        }

        if (entries.Count > MaxEntries)
        {
            entries.RemoveRange(0, entries.Count - MaxEntries);
        }

        return entries;
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _broadcaster.Dispose();
    }
}
