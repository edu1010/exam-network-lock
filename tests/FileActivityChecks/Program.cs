using System.Reflection;
using ExamShared;
#if LINUX_CLIENT
using Monitor = ExamLockClient.Core.Monitoring.FileActivityMonitor;
#else
using Monitor = ExamLockClient.FileActivityMonitor;
#endif

static void Check(bool condition, string description)
{
    if (!condition) throw new InvalidOperationException(description);
    Console.WriteLine("PASS: " + description);
}
static string[] Args(params string[] args) => FileActivityNoiseFilter.DocumentArguments(args).ToArray();
Check(Args("eclipse", "-startup", "/opt/eclipse/launcher.jar", "/home/student/answer.java").SequenceEqual(["/home/student/answer.java"]), "Eclipse startup library excluded; student document retained");
Check(Args("java.exe", "-cp", "C:/jdk/lib/runtime.jar", "Main").SequenceEqual(["Main"]), "Java classpath excluded");
Check(Args("notepad", "-startup", "/outside/notes.txt").Contains("/outside/notes.txt"), "Startup exclusions scoped to the matching application");
Check(Args("code", "--", "--user-data-dir", "/outside/notes.txt").Contains("/outside/notes.txt"), "End-of-options preserves document arguments");
Check(Args("chrome", "--log-file=/tmp/browser.log", "/outside/notes.txt").SequenceEqual(["/outside/notes.txt"]), "Inline option does not consume the next document");
Check(Args("code", "--user-data-dir", "--wait", "/outside/notes.txt").Contains("/outside/notes.txt"), "Missing option value does not hide following document");
Check(FileActivityNoiseFilter.IsEditorMetadata(@".VSCODE\Settings.JSON", true), "Windows metadata paths are case insensitive");
Check(!FileActivityNoiseFilter.IsEditorMetadata(".VSCODE/settings.json", false), "Linux metadata paths are case sensitive");
Check(!FileActivityNoiseFilter.IsEditorMetadata(".vscode/notes.pdf", true), "No blanket exclusion of editor directories");
Check(!FileActivityNoiseFilter.IsEditorMetadata("../.vscode/settings.json", true), "Metadata exemption stays within work folder");

var root = Directory.CreateTempSubdirectory("exam-file-check-").FullName;
try
{
    var work = Directory.CreateDirectory(Path.Combine(root, "work")).FullName;
    var outside = Path.Combine(root, "notes.txt");
    File.WriteAllText(outside, "fixture");
    using var monitor = Create(work, [".txt"], []);
    // Isolate argument handling from the existing per-user temp exclusions in this temporary fixture.
    typeof(Monitor).GetField("_excludedRoots", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(monitor, Array.Empty<string>());
    var outsideCount = 0;
    var unknownCount = 0;
    var forbiddenCount = 0;
    monitor.OutsideFolderDetected += _ => outsideCount++;
    monitor.UnknownFileDetected += _ => unknownCount++;
    monitor.ForbiddenFileDetected += _ => forbiddenCount++;
    Invoke(monitor, "InspectCommandLine", $"eclipse -startup \"{outside}\"");
    Check(outsideCount == 0, "Monitor does not flag application startup data outside work folder");
    Invoke(monitor, "InspectCommandLine", $"notepad \"{outside}\"");
    Check(outsideCount == 1, "Monitor still flags an explicit document outside work folder");
    var metadata = Path.Combine(work, ".vscode", "settings.json");
    Directory.CreateDirectory(Path.GetDirectoryName(metadata)!);
    File.WriteAllText(metadata, "{}");
    Invoke(monitor, "InspectWatchedFile", metadata);
    Check(unknownCount == 0, "Generated editor settings do not trigger unknown-extension warning");
    Invoke(monitor, "InspectCommandLine", $"notepad \"{metadata}\"");
    Check(forbiddenCount == 1, "Explicitly opening metadata still checks allowed extensions");
    Invoke(monitor, "InspectWatchedFile", Path.Combine(work, ".vscode", "notes.pdf"));
    Check(unknownCount == 1, "Other files in editor directory are still checked");
    var dottedDirectory = Directory.CreateDirectory(Path.Combine(work, "project.pdf")).FullName;
    Invoke(monitor, "InspectWatchedFile", dottedDirectory);
    Check(unknownCount == 1, "Directory with dotted name is not treated as a document");
    using var blocked = Create(work, [], [".json"]);
    var blockedCount = 0;
    blocked.ForbiddenFileDetected += _ => blockedCount++;
    Invoke(blocked, "InspectWatchedFile", metadata);
    Check(blockedCount == 1, "Explicitly prohibited extension overrides metadata exclusion");
}
finally { Directory.Delete(root, recursive: true); }

static Monitor Create(string work, string[] allowed, string[] blocked)
{
#if LINUX_CLIENT
    return new(new ExamLockClient.Core.Platform.LinuxPlatform(), allowed, work, true, blockedExtensions: blocked);
#else
    return new(allowed, work, true, blockedExtensions: blocked);
#endif
}
static void Invoke(Monitor monitor, string method, string path) =>
    typeof(Monitor).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(monitor, [path]);
