using System.Reflection;
using ExamLockClient.Core.Monitoring;
using ExamLockClient.Core.Platform;

// This child deliberately fills stderr before closing stdout. Sequential pipe reads deadlock.
if (args.Contains("--emit"))
{
    Console.Error.Write(new string('e', 256 * 1024));
    Console.Out.Write(new string('o', 256 * 1024));
    return;
}

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
    Console.WriteLine("PASS: " + message);
}

Check(ProcessNames.Bare(@"C:\Program Files\Chrome\CHROME.EXE") == "chrome", "Windows executable normalization");
Check(ProcessNames.Bare("/usr/bin/python3.11") == "python3.11", "Linux versioned executable name preserved");
Check(AiProcessClassifier.IsDedicatedAiTool(new ProcessInfo(1, "node", null,
    "node /opt/tools/@anthropic-ai/claude-code/cli.js")), "Node-hosted Claude Code detection");
Check(AiProcessClassifier.IsDedicatedAiTool(new ProcessInfo(2, "python3", null,
    "python3 /opt/tools/aider --help")), "Python-hosted AI tool detection");
Check(!AiProcessClassifier.IsDedicatedAiTool(new ProcessInfo(3, "python3", null,
    "python3 homework.py")), "Ordinary Python program is not an AI tool");

var host = Environment.ProcessPath!;
var childArgs = Path.GetFileNameWithoutExtension(host).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
    ? new[] { Assembly.GetExecutingAssembly().Location, "--emit" }
    : new[] { "--emit" };
var read = Task.Run(() =>
{
    var ok = Shell.Run(host, out var output, out var error, childArgs);
    return ok && output.Length == 256 * 1024 && error.Length == 256 * 1024;
});
Check(await Task.WhenAny(read, Task.Delay(TimeSpan.FromSeconds(20))) == read,
    "Large stdout/stderr complete without deadlock");
Check(await read, "Both redirected streams captured completely");
Check(!Shell.Run(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), out _, out var failure)
    && failure.Length > 0, "Missing command reports failure");

var platform = new ProcessTestPlatform { Processes = [new(101, "firefox", null, null), new(102, "helper", null, null)] };
var prohibited = new List<string>();
var unknown = new List<string>();
using var monitor = new ProcessMonitor(platform, ["code"], ["firefox.exe"]);
monitor.BlockedProcessDetected += prohibited.Add;
monitor.UnknownProcessStarted += unknown.Add;
monitor.Start();
monitor.Dispose(); // Poll explicitly below; avoid timer timing in regression tests.
Check(prohibited.SequenceEqual(["firefox"]) && unknown.Count == 0, "Startup catches prohibited app but exempts existing helper");
var poll = typeof(ProcessMonitor).GetMethod("Poll", BindingFlags.Instance | BindingFlags.NonPublic)!;
poll.Invoke(monitor, [true]);
Check(prohibited.Count == 1, "Same running process is not repeatedly reported");
platform.Processes = [new(102, "helper", null, null), new(103, "systemd", null, null), new(104, "new-helper", null, null)];
poll.Invoke(monitor, [true]);
Check(unknown.SequenceEqual(["new-helper"]), "System process exempt; new auxiliary process gets a warning");
platform.Processes = [new(101, "firefox", null, null)];
poll.Invoke(monitor, [true]);
Check(prohibited.Count == 2, "Reused PID after exit is detected again");

internal sealed class ProcessTestPlatform : IPlatform
{
    public IReadOnlyList<ProcessInfo> Processes { get; set; } = [];
    public string Name => "Test";
    public bool IsElevated => false;
    public IReadOnlyList<ProcessInfo> GetProcessList() => Processes;
    public ProcessInfo? TryGetProcess(int pid) => Processes.FirstOrDefault(p => p.Pid == pid);
    public bool TryRelaunchElevated(string executablePath, IReadOnlyList<string> args) => throw new NotSupportedException();
    public bool DisableWifi(out string error) => throw new NotSupportedException();
    public bool EnableWifi(out string error) => throw new NotSupportedException();
    public Task<(bool ok, string error)> SetBluetoothAsync(bool on) => throw new NotSupportedException();
    public bool TryGetTcpConnections(out List<TcpConnectionInfo> connections) => throw new NotSupportedException();
    public IEnumerable<string> GetDnsCacheHosts() => [];
    public bool TrySetVolume(int percent) => throw new NotSupportedException();
    public void Beep(int frequencyHz, int durationMs) => throw new NotSupportedException();
}
