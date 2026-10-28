using System.Net;
using System.Security.Cryptography;
using ExamShared;

// Run with XDG_CONFIG_HOME (Linux) pointing at a scratch folder: the checks write default.config there.

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
    Console.WriteLine("PASS: " + message);
}

static string Signed(string adminPassword, string[] monitorTargets, bool isDefault = true)
{
    var salt = RandomNumberGenerator.GetBytes(16);
    var payload = new ConfigPayload
    {
        Iterations = 10_000,
        AdminSaltBase64 = Convert.ToBase64String(salt),
        AdminPasswordHashBase64 = PasswordHasher.HashPassword(adminPassword, salt, 10_000, 32),
        MonitorTargets = monitorTargets,
        IsDefaultConfig = isDefault ? true : null
    };
    var json = ConfigSerializer.SerializePayload(payload);
    return ConfigSerializer.SerializeEnvelope(new ConfigEnvelope { Payload = payload, HmacBase64 = ConfigIntegrityService.ComputeHmacBase64(json) });
}

var first = Signed("teacher-1", ["10.0.0.5"]);
var second = Signed("teacher-2", ["10.0.0.9"]);
Check(DefaultConfigStore.TryParseSigned(first) is not null, "Signed config is accepted");
Check(DefaultConfigStore.TryParseSigned(first.Replace("10.0.0.5", "10.0.0.6")) is null, "Tampered config is rejected");

if (File.Exists(DefaultConfigStore.FilePath)) File.Delete(DefaultConfigStore.FilePath);
ConfigPayload? running = null;
var examRunning = false;
using var receiver = new ConfigPushReceiver(() => DefaultConfigStore.TryLoad() ?? running, () => !examRunning);
var updates = 0;
receiver.DefaultConfigUpdated += () => Interlocked.Increment(ref updates);
string? examPath = null;
receiver.ExamConfigReceived += p => examPath = p;
receiver.Start();

Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", first, "x") == ConfigPushErrors.NoAuthority, "Client without any config refuses pushes");

running = DefaultConfigStore.TryParseSigned(first)!.Payload;
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", first, "wrong") == ConfigPushErrors.Auth, "Wrong password B is rejected");
Check(!File.Exists(DefaultConfigStore.FilePath), "Rejected push writes nothing");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", first, "teacher-1") is null, "First default deployed with the running config's password B");
Check(DefaultConfigStore.TryLoad()?.MonitorTargets.Single() == "10.0.0.5", "Pushed config saved as default");

running = null;
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", second, "teacher-2") == ConfigPushErrors.Auth, "Replacing the default needs the CURRENT default's password");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", second.Replace("10.0.0.9", "10.0.0.1"), "teacher-1") == ConfigPushErrors.Invalid, "Unsigned config is refused even with the right password");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", second, "teacher-1") is null, "Default replaced with the current default's password");
Check(DefaultConfigStore.TryLoad()?.MonitorTargets.Single() == "10.0.0.9", "New default saved");
await Task.Delay(100);
Check(updates == 2, "Client notified once per accepted push");

var exam = Signed("exam-pwd", [], isDefault: false);
Check(!ConfigSerializer.SerializeEnvelope(ConfigSerializer.DeserializeEnvelope(exam)).Contains("isDefaultConfig"),
    "Exam configs omit the default flag, so older signatures stay valid");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "exam.config", exam, "teacher-2") == ConfigPushErrors.WrongKind,
    "Exam config cannot be installed as the default");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Exam, "default.config", second, "teacher-2") == ConfigPushErrors.WrongKind,
    "Default config cannot be started as an exam");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Exam, "parcial 1.config", exam, "teacher-1") == ConfigPushErrors.Auth,
    "Exam push needs the default's password B");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Exam, "parcial 1.config", exam, "teacher-2") is null,
    "Exam pushed with the default's password B");
await Task.Delay(100);
Check(examPath is not null && File.ReadAllText(examPath) == exam && Path.GetFileName(examPath) == "exam.config"
    && Path.GetFileName(Path.GetDirectoryName(examPath)!).StartsWith("parcial1_"), "Exam saved in its own named folder");
Check(DefaultConfigStore.TryLoad()?.MonitorTargets.Single() == "10.0.0.9", "Exam push leaves the default untouched for the next launch");
examRunning = true;
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Exam, "x.config", exam, "teacher-2") == ConfigPushErrors.Busy,
    "Exam in progress is never replaced");
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Exam, "../../evil.config", exam, "teacher-2") == ConfigPushErrors.Busy,
    "Busy check happens before anything is written");
examRunning = false;
var traversal = await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Exam, "../../evil.config", exam, "teacher-2");
await Task.Delay(100);
Check(traversal is null && Path.GetDirectoryName(Path.GetDirectoryName(examPath!)) == PushedExamStore.Root, "File name cannot escape the exam folder");
Directory.Delete(PushedExamStore.Root, recursive: true);

receiver.Dispose();
Check(await ConfigPushSender.PushAsync(IPAddress.Loopback, ConfigPushTargets.Default, "default.config", second, "teacher-2") == ConfigPushErrors.Unreachable, "Closed client reported as unreachable");
