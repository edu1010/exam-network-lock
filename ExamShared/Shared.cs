using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ExamShared;

public sealed class ConfigPayload
{
    public int Version { get; init; } = 2;

    // Password A ("Restore Wi-Fi"): re-enables radios. Existing fields.
    public string SaltBase64 { get; init; } = "";
    public int Iterations { get; init; }
    public string PasswordHashBase64 { get; init; } = "";

    // Password B ("Close / Admin"): silences the shield and allows closing.
    public string AdminSaltBase64 { get; init; } = "";
    public string AdminPasswordHashBase64 { get; init; } = "";

    public string LogSecretBase64 { get; init; } = "";

    // Radios. Disabling is best-effort; the AI shield is the safety net.
    public bool DisableWifi { get; init; } = true;
    public bool DisableBluetooth { get; init; }

    // AI shield: monitor active TCP connections against a blocklist.
    public bool AiShieldEnabled { get; init; } = true;
    public string[] AiBlocklist { get; init; } = Array.Empty<string>();
    public bool RaiseVolumeOnAi { get; init; } = true;
    public bool BeepOnViolation { get; init; } = true;

    // Allowed programs (exe names, e.g. "eclipse.exe") and file extensions (e.g. ".java").
    public string[] AllowedProcesses { get; init; } = Array.Empty<string>();
    public string[] AllowedFileExtensions { get; init; } = Array.Empty<string>();

    // Exam work folder: work allowed here and in subfolders.
    // The base is resolved on the STUDENT machine (per-user), so it is portable across
    // laptops with different usernames. See WorkFolderModes / WorkFolderResolver.
    public string WorkFolderMode { get; init; } = WorkFolderModes.ConfigFolder;
    public string WorkFolderRelative { get; init; } = ""; // optional subfolder under the base
    public string WorkFolder { get; init; } = "";         // absolute path, only for "Absolute" mode
    public bool RestrictToWorkFolder { get; init; }
}

public static class WorkFolderModes
{
    public const string ConfigFolder = "ConfigFolder"; // folder where exam.config lives
    public const string Desktop = "Desktop";           // the student's Desktop
    public const string Documents = "Documents";       // the student's Documents
    public const string Absolute = "Absolute";         // a fixed path identical on every machine
}

/// <summary>
/// Resolves the configured work folder to an absolute path on the machine where the client
/// runs. Using per-user special folders keeps the exam folder portable: the same config works
/// on every laptop regardless of the Windows username.
/// </summary>
public static class WorkFolderResolver
{
    public static string Resolve(ConfigPayload config, string configDir)
    {
        if (!config.RestrictToWorkFolder)
        {
            return "";
        }

        var relative = (config.WorkFolderRelative ?? "").Trim();

        if (config.WorkFolderMode == WorkFolderModes.Absolute)
        {
            return (config.WorkFolder ?? "").Trim();
        }

        var baseDir = config.WorkFolderMode switch
        {
            WorkFolderModes.Desktop => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            WorkFolderModes.Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            _ => configDir // ConfigFolder (default)
        };

        if (string.IsNullOrEmpty(baseDir))
        {
            return "";
        }

        return relative.Length > 0 ? Path.Combine(baseDir, relative) : baseDir;
    }
}

public static class ConfigDefaults
{
    // Hostnames/IP fragments considered "AI services". Matched as substrings of the
    // resolved hostname; entries that are already IPs are used as-is.
    public static readonly string[] DefaultAiBlocklist =
    {
        "claude.ai",
        "anthropic.com",
        "openai.com",
        "chatgpt.com",
        "oaistatic.com",
        "gemini.google.com",
        "bard.google.com",
        "generativelanguage.googleapis.com",
        "copilot.microsoft.com",
        "perplexity.ai",
        "deepseek.com",
        "poe.com",
        "x.ai",
        "grok.com",
        "huggingface.co",
        "mistral.ai",
        "cohere.com",
        "you.com",
        "phind.com",
        "character.ai",
    };
}

public static class LogEvents
{
    public const string AppStarted = "APP_STARTED";
    public const string ConfigValid = "CONFIG_VALID";
    public const string UncleanPreviousSession = "UNCLEAN_PREVIOUS_SESSION_DETECTED";

    public const string WifiDisabled = "WIFI_DISABLED";
    public const string WifiDisableFailed = "WIFI_DISABLE_FAILED";
    public const string WifiEnabled = "WIFI_ENABLED";
    public const string WifiEnableFailed = "WIFI_ENABLE_FAILED";
    public const string WifiRestored = "WIFI_RESTORED";

    public const string BluetoothDisabled = "BT_DISABLED";
    public const string BluetoothEnabled = "BT_ENABLED";
    public const string BluetoothFailed = "BT_FAILED";

    public const string AiDetected = "AI_DETECTED";
    public const string AiCleared = "AI_CLEARED";

    public const string UnknownProcess = "UNKNOWN_PROCESS";
    public const string ForbiddenFile = "FORBIDDEN_FILE";
    public const string UnknownFile = "UNKNOWN_FILE";
    public const string OutsideFolder = "OUTSIDE_FOLDER";

    public const string ShieldGreen = "SHIELD_GREEN";
    public const string ShieldYellow = "SHIELD_YELLOW";
    public const string ShieldRed = "SHIELD_RED";

    public const string UnlockSuccess = "UNLOCK_SUCCESS";
    public const string UnlockFailed = "UNLOCK_FAILED";
    public const string AdminClose = "ADMIN_CLOSE";
    public const string AdminAuthFailed = "ADMIN_AUTH_FAILED";
    public const string NormalExit = "NORMAL_EXIT";
}

public sealed class ConfigEnvelope
{
    public ConfigPayload Payload { get; init; } = new();
    public string HmacBase64 { get; init; } = "";
}

public static class PasswordHasher
{
    public static string HashPassword(string password, byte[] salt, int iterations, int outputBytes)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(outputBytes);
        return Convert.ToBase64String(hash);
    }

    public static bool VerifyPassword(string password, string saltBase64, int iterations, string expectedHashBase64)
    {
        var salt = Convert.FromBase64String(saltBase64);
        var expected = Convert.FromBase64String(expectedHashBase64);
        var actual = Convert.FromBase64String(HashPassword(password, salt, iterations, expected.Length));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}

public static class ConfigIntegrityService
{
    private static readonly byte[] HmacKey = Encoding.UTF8.GetBytes("ExamConfigTeacherSecret_v1");

    public static string ComputeHmacBase64(string payloadJson)
    {
        using var hmac = new HMACSHA256(HmacKey);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(payloadJson));
        return Convert.ToBase64String(mac);
    }

    public static bool VerifyHmac(string payloadJson, string expectedBase64)
    {
        var expected = Convert.FromBase64String(expectedBase64);
        var actual = Convert.FromBase64String(ComputeHmacBase64(payloadJson));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}

public static class ConfigSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string SerializePayload(ConfigPayload payload)
    {
        return JsonSerializer.Serialize(payload, Options);
    }

    public static string SerializeEnvelope(ConfigEnvelope envelope)
    {
        return JsonSerializer.Serialize(envelope, Options);
    }

    public static ConfigEnvelope DeserializeEnvelope(string json)
    {
        var env = JsonSerializer.Deserialize<ConfigEnvelope>(json, Options);
        if (env is null)
        {
            throw new InvalidDataException("Invalid config format.");
        }

        return env;
    }
}

public sealed class LogEntry
{
    public int Sequence { get; init; }
    public string Timestamp { get; init; } = "";
    public string EventType { get; init; } = "";
    public string? EventData { get; init; }
    public string PrevHmacBase64 { get; init; } = "";
    public string HmacBase64 { get; init; } = "";
}

public sealed class SecureLogService
{
    private readonly string _logPath;
    private readonly byte[] _secret;
    private string _lastHmac;
    private int _sequence;

    public SecureLogService(string logPath, string logSecretBase64)
    {
        _logPath = logPath;
        _secret = Convert.FromBase64String(logSecretBase64);
        _lastHmac = TryLoadLastHmac(logPath) ?? "GENESIS";
        _sequence = TryLoadLastSequence(logPath) + 1;
    }

    public void Append(string eventType, string? eventData = null)
    {
        var entry = CreateEntry(eventType, eventData);
        var json = JsonSerializer.Serialize(entry);
        File.AppendAllText(_logPath, json + Environment.NewLine, Encoding.UTF8);
        _lastHmac = entry.HmacBase64;
        _sequence++;
    }

    private LogEntry CreateEntry(string eventType, string? eventData)
    {
        var timestamp = DateTime.Now.ToString("O");
        var data = eventData ?? string.Empty;
        var payload = $"{_sequence}|{timestamp}|{eventType}|{data}|{_lastHmac}";
        var hmac = ComputeHmac(payload);
        return new LogEntry
        {
            Sequence = _sequence,
            Timestamp = timestamp,
            EventType = eventType,
            EventData = eventData,
            PrevHmacBase64 = _lastHmac,
            HmacBase64 = hmac
        };
    }

    private string ComputeHmac(string text)
    {
        using var hmac = new HMACSHA256(_secret);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        return Convert.ToBase64String(mac);
    }

    private static string? TryLoadLastHmac(string logPath)
    {
        if (!File.Exists(logPath))
        {
            return null;
        }

        var lastLine = ReadLastNonEmptyLine(logPath);
        if (lastLine is null)
        {
            return null;
        }

        try
        {
            var entry = JsonSerializer.Deserialize<LogEntry>(lastLine);
            return entry?.HmacBase64;
        }
        catch
        {
            return null;
        }
    }

    private static int TryLoadLastSequence(string logPath)
    {
        if (!File.Exists(logPath))
        {
            return 0;
        }

        var lastLine = ReadLastNonEmptyLine(logPath);
        if (lastLine is null)
        {
            return 0;
        }

        try
        {
            var entry = JsonSerializer.Deserialize<LogEntry>(lastLine);
            return entry?.Sequence ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static string? ReadLastNonEmptyLine(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(fs, Encoding.UTF8, true, 4096, true);
        string? last = null;
        while (!reader.EndOfStream)
        {
            var line = reader.ReadLine();
            if (!string.IsNullOrWhiteSpace(line))
            {
                last = line;
            }
        }

        return last;
    }
}

public sealed class SessionStateService
{
    private readonly string _sessionLockPath;

    public SessionStateService(string sessionLockPath)
    {
        _sessionLockPath = sessionLockPath;
    }

    public bool HasUncleanPreviousSession()
    {
        return File.Exists(_sessionLockPath);
    }

    public void MarkSessionStart()
    {
        File.WriteAllText(_sessionLockPath, DateTime.Now.ToString("O"), Encoding.UTF8);
    }

    public void MarkSessionCleanEnd()
    {
        if (File.Exists(_sessionLockPath))
        {
            File.Delete(_sessionLockPath);
        }
    }
}
