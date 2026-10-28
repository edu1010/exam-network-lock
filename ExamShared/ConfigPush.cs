using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ExamShared;

/// <summary>
/// The student client's "default" (base) config: a signed exam.config kept in the user's profile
/// that the client loads on every start when no exam config is given. It carries the teacher
/// monitor IPs, so the monitor sees the student as soon as the app opens; the real exam config can
/// still be opened on top of it.
/// </summary>
public static class DefaultConfigStore
{
    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify),
        "ExamLock", "default.config");

    public static bool IsDefaultPath(string path)
    {
        try
        {
            return string.Equals(Path.GetFullPath(path), Path.GetFullPath(FilePath), StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Parses a config file's text and checks its signature; null if it is not a valid config.</summary>
    public static ConfigEnvelope? TryParseSigned(string json)
    {
        try
        {
            var envelope = ConfigSerializer.DeserializeEnvelope(json);
            var payloadJson = ConfigSerializer.SerializePayload(envelope.Payload);
            return ConfigIntegrityService.VerifyHmac(payloadJson, envelope.HmacBase64) ? envelope : null;
        }
        catch
        {
            return null;
        }
    }

    public static ConfigPayload? TryLoad()
    {
        try
        {
            return File.Exists(FilePath) ? TryParseSigned(File.ReadAllText(FilePath, Encoding.UTF8))?.Payload : null;
        }
        catch
        {
            return null;
        }
    }

    public static void Save(string json)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, json, Encoding.UTF8);
        File.Move(temp, FilePath, overwrite: true);
    }
}

/// <summary>
/// Exam configs pushed from the monitor. Each one gets its own visible folder (its log and, in the
/// "where exam.config is" mode, the work folder live next to it). They are never searched at start
/// up, so the next launch goes back to the default config.
/// </summary>
public static class PushedExamStore
{
    public static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify), "ExamLock");

    /// <summary>Saves to ~/ExamLock/&lt;name&gt;_&lt;date&gt;/exam.config and returns that path.</summary>
    public static string Save(string json, string fileName)
    {
        var name = Path.GetFileNameWithoutExtension(Path.GetFileName(fileName ?? ""));
        name = string.Concat(name.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_'));
        if (name.Length == 0 || name.Equals("exam", StringComparison.OrdinalIgnoreCase))
        {
            name = "exam";
        }

        var folder = Path.Combine(Root, $"{name[..Math.Min(name.Length, 60)]}_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, "exam.config");
        File.WriteAllText(path, json, Encoding.UTF8);
        return path;
    }
}

/// <summary>What a push installs on the student.</summary>
public static class ConfigPushTargets
{
    public const string Default = "default"; // replaces the saved default config
    public const string Exam = "exam";       // starts this exam now; the default stays for the next launch
}

public static class ConfigPushErrors
{
    public const string Auth = "auth";             // wrong password B
    public const string Invalid = "invalid";       // pushed file is not a signed config
    public const string NoAuthority = "noconfig";  // client has no config to check the password against
    public const string Save = "save";             // client could not write the file
    public const string Busy = "busy";             // exam push to a client already running an exam
    public const string WrongKind = "kind";        // default config sent as exam, or the other way round
    public const string Unreachable = "unreachable";
}

/// <summary>
/// Monitor → student push of a config (new default, or an exam to start) over TCP (<see cref="MonitorProtocol.ConfigPushPort"/>).
/// The teacher authenticates with password B of the config the student already has, as a
/// challenge-response: the client sends the PBKDF2 salt and a fresh nonce, the monitor answers with
/// HMAC(PBKDF2(password), nonce + target + file name + config). The password never travels and a capture cannot be
/// replayed. Messages are single JSON lines.
/// </summary>
internal static class ConfigPushProtocol
{
    public const int MaxLineBytes = 1024 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    public sealed class Challenge
    {
        public string Kind { get; init; } = "challenge";
        public string SaltBase64 { get; init; } = "";
        public int Iterations { get; init; }
        public int HashBytes { get; init; }
        public string NonceBase64 { get; init; } = "";
    }

    public sealed class Request
    {
        public string Kind { get; init; } = "push";
        public string Target { get; init; } = ConfigPushTargets.Default;
        public string FileName { get; init; } = "";
        public string ConfigJson { get; init; } = "";
        public string MacBase64 { get; init; } = "";
    }

    public sealed class Result
    {
        public string Kind { get; init; } = "result";
        public bool Ok { get; init; }
        public string Error { get; init; } = "";
    }

    public static byte[] ComputeMac(byte[] key, byte[] nonce, string target, string fileName, string configJson)
    {
        using var hmac = new HMACSHA256(key);
        var signed = Encoding.UTF8.GetBytes(target + "\n" + fileName + "\n" + configJson);
        return hmac.ComputeHash(nonce.Concat(signed).ToArray());
    }

    public static async Task WriteAsync(Stream stream, object message, CancellationToken ct)
    {
        var bytes = MonitorProtocol.Serialize(message);
        await stream.WriteAsync(bytes, ct);
        await stream.WriteAsync(new[] { (byte)'\n' }, ct);
    }

    /// <summary>Reads '\n'-terminated lines with a size cap (StreamReader.ReadLine has none).</summary>
    public sealed class LineReader(Stream stream)
    {
        private readonly byte[] _buffer = new byte[8192];
        private int _start;
        private int _end;

        public async Task<byte[]?> ReadAsync(CancellationToken ct)
        {
            using var line = new MemoryStream();
            while (true)
            {
                if (_start == _end)
                {
                    _start = 0;
                    _end = await stream.ReadAsync(_buffer, ct);
                    if (_end == 0)
                    {
                        return null;
                    }
                }

                var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
                var stop = newline < 0 ? _end : newline;
                line.Write(_buffer, _start, stop - _start);
                if (line.Length > MaxLineBytes)
                {
                    return null;
                }

                _start = newline < 0 ? _end : newline + 1;
                if (newline >= 0)
                {
                    return line.ToArray();
                }
            }
        }
    }
}

/// <summary>Student side: accepts config pushes (new default or exam to start) from the teacher's monitor.</summary>
public sealed class ConfigPushReceiver : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Any, MonitorProtocol.ConfigPushPort);
    private readonly Func<ConfigPayload?> _authority;
    private readonly Func<bool> _acceptsExam;
    private volatile bool _running;

    /// <summary>Raised (on a worker thread) after a pushed config was verified and saved as the default.</summary>
    public event Action? DefaultConfigUpdated;

    /// <summary>Raised (on a worker thread) with the saved path of a verified exam config to start now.</summary>
    public event Action<string>? ExamConfigReceived;

    /// <param name="authority">Config whose password B authorizes a push (normally the saved default).</param>
    /// <param name="acceptsExam">Whether an exam may be started now (i.e. no exam is running).</param>
    public ConfigPushReceiver(Func<ConfigPayload?> authority, Func<bool> acceptsExam)
    {
        _authority = authority;
        _acceptsExam = acceptsExam;
    }

    public void Start()
    {
        _listener.Start();
        _running = true;
        _ = AcceptLoopAsync();
    }

    private async Task AcceptLoopAsync()
    {
        while (_running)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync();
            }
            catch
            {
                if (!_running)
                {
                    return;
                }

                continue;
            }

            _ = HandleAsync(client);
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using var _ = client;
        using var cts = new CancellationTokenSource(ConfigPushProtocol.Timeout);
        try
        {
            var stream = client.GetStream();
            var authority = _authority();
            if (authority is null)
            {
                await Reply(stream, ConfigPushErrors.NoAuthority, cts.Token);
                return;
            }

            var key = Convert.FromBase64String(authority.AdminPasswordHashBase64);
            var nonce = RandomNumberGenerator.GetBytes(32);
            await ConfigPushProtocol.WriteAsync(stream, new ConfigPushProtocol.Challenge
            {
                SaltBase64 = authority.AdminSaltBase64,
                Iterations = authority.Iterations,
                HashBytes = key.Length,
                NonceBase64 = Convert.ToBase64String(nonce)
            }, cts.Token);

            var line = await new ConfigPushProtocol.LineReader(stream).ReadAsync(cts.Token);
            var request = line is null ? null : MonitorProtocol.Deserialize<ConfigPushProtocol.Request>(line);
            if (request is null)
            {
                return;
            }

            var expected = ConfigPushProtocol.ComputeMac(key, nonce, request.Target, request.FileName, request.ConfigJson);
            if (!CryptographicOperations.FixedTimeEquals(expected, Convert.FromBase64String(request.MacBase64)))
            {
                await Reply(stream, ConfigPushErrors.Auth, cts.Token);
                return;
            }

            var pushed = DefaultConfigStore.TryParseSigned(request.ConfigJson);
            if (pushed is null)
            {
                await Reply(stream, ConfigPushErrors.Invalid, cts.Token);
                return;
            }

            var exam = request.Target == ConfigPushTargets.Exam;
            if (exam == (pushed.Payload.IsDefaultConfig == true))
            {
                await Reply(stream, ConfigPushErrors.WrongKind, cts.Token);
                return;
            }

            if (exam && !_acceptsExam())
            {
                await Reply(stream, ConfigPushErrors.Busy, cts.Token);
                return;
            }

            string examPath = "";
            try
            {
                if (exam)
                {
                    examPath = PushedExamStore.Save(request.ConfigJson, request.FileName);
                }
                else
                {
                    DefaultConfigStore.Save(request.ConfigJson);
                }
            }
            catch
            {
                await Reply(stream, ConfigPushErrors.Save, cts.Token);
                return;
            }

            await Reply(stream, "", cts.Token);
            if (exam)
            {
                ExamConfigReceived?.Invoke(examPath);
            }
            else
            {
                DefaultConfigUpdated?.Invoke();
            }
        }
        catch
        {
            // Malformed request, timeout or dropped connection: nothing to do.
        }
    }

    private static Task Reply(Stream stream, string error, CancellationToken ct) =>
        ConfigPushProtocol.WriteAsync(stream, new ConfigPushProtocol.Result { Ok = error.Length == 0, Error = error }, ct);

    public void Dispose()
    {
        _running = false;
        _listener.Stop();
    }
}

/// <summary>Teacher side: sends a config to one student, as its new default or as an exam to start.</summary>
public static class ConfigPushSender
{
    /// <param name="target">One of <see cref="ConfigPushTargets"/>.</param>
    /// <param name="fileName">Original file name; names the student's exam folder.</param>
    /// <returns>Null on success, otherwise one of <see cref="ConfigPushErrors"/>.</returns>
    public static async Task<string?> PushAsync(IPAddress address, string target, string fileName, string configJson, string password)
    {
        using var cts = new CancellationTokenSource(ConfigPushProtocol.Timeout);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(address, MonitorProtocol.ConfigPushPort, cts.Token);
            var stream = client.GetStream();
            var reader = new ConfigPushProtocol.LineReader(stream);

            var line = await reader.ReadAsync(cts.Token);
            if (line is null)
            {
                return ConfigPushErrors.Unreachable;
            }

            if (MonitorProtocol.KindOf(line) == "result")
            {
                return MonitorProtocol.Deserialize<ConfigPushProtocol.Result>(line)?.Error ?? ConfigPushErrors.Unreachable;
            }

            var challenge = MonitorProtocol.Deserialize<ConfigPushProtocol.Challenge>(line);
            if (challenge is null)
            {
                return ConfigPushErrors.Unreachable;
            }

            // PBKDF2 is deliberately slow; keep it off the UI thread.
            var key = await Task.Run(() => Convert.FromBase64String(PasswordHasher.HashPassword(
                password, Convert.FromBase64String(challenge.SaltBase64), challenge.Iterations, challenge.HashBytes)));
            var mac = ConfigPushProtocol.ComputeMac(key, Convert.FromBase64String(challenge.NonceBase64), target, fileName, configJson);
            await ConfigPushProtocol.WriteAsync(stream, new ConfigPushProtocol.Request
            {
                Target = target,
                FileName = fileName,
                ConfigJson = configJson,
                MacBase64 = Convert.ToBase64String(mac)
            }, cts.Token);

            line = await reader.ReadAsync(cts.Token);
            var result = line is null ? null : MonitorProtocol.Deserialize<ConfigPushProtocol.Result>(line);
            return result is null ? ConfigPushErrors.Unreachable : result.Ok ? null : result.Error;
        }
        catch
        {
            return ConfigPushErrors.Unreachable;
        }
    }
}
