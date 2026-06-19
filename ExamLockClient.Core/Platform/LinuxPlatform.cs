using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace ExamLockClient.Core.Platform;

/// <summary>
/// Linux backend. Radios are toggled with NetworkManager (nmcli) or rfkill; active connections and
/// their owning process come from /proc/net/tcp{,6} cross-referenced with /proc/&lt;pid&gt;/fd; process
/// detail comes from /proc; audio uses PulseAudio/PipeWire tools (pactl + paplay).
/// </summary>
public sealed class LinuxPlatform : IPlatform
{
    public string Name => "Linux";

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEuid();

    public bool IsElevated
    {
        get
        {
            try
            {
                return GetEuid() == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    public bool TryRelaunchElevated(string executablePath, IReadOnlyList<string> args)
    {
        try
        {
            // pkexec drops most of the environment, so a GUI relaunch must carry DISPLAY/XAUTHORITY
            // (and the Wayland equivalent) through explicitly, otherwise the new process cannot
            // connect to the user's session and would exit immediately.
            var passthrough = new List<string> { "env" };
            AddEnv(passthrough, "DISPLAY");
            AddEnv(passthrough, "XAUTHORITY");
            AddEnv(passthrough, "WAYLAND_DISPLAY");
            AddEnv(passthrough, "XDG_RUNTIME_DIR");

            passthrough.Add(executablePath);
            passthrough.AddRange(args);

            return Shell.Run("pkexec", passthrough.ToArray());
        }
        catch
        {
            return false;
        }

        static void AddEnv(List<string> list, string key)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrEmpty(value))
            {
                list.Add($"{key}={value}");
            }
        }
    }

    // ---- Radios ----

    public bool DisableWifi(out string error)
    {
        if (Shell.Run("nmcli", out _, out var nmErr, "radio", "wifi", "off"))
        {
            error = string.Empty;
            return true;
        }

        if (Shell.Run("rfkill", out _, out var rfErr, "block", "wifi"))
        {
            error = string.Empty;
            return true;
        }

        error = FirstNonEmpty(rfErr, nmErr, "nmcli/rfkill unavailable");
        return false;
    }

    public bool EnableWifi(out string error)
    {
        if (Shell.Run("nmcli", out _, out var nmErr, "radio", "wifi", "on"))
        {
            error = string.Empty;
            return true;
        }

        if (Shell.Run("rfkill", out _, out var rfErr, "unblock", "wifi"))
        {
            error = string.Empty;
            return true;
        }

        error = FirstNonEmpty(rfErr, nmErr, "nmcli/rfkill unavailable");
        return false;
    }

    public Task<(bool ok, string error)> SetBluetoothAsync(bool on) => Task.Run(() =>
    {
        var action = on ? "unblock" : "block";
        if (Shell.Run("rfkill", out _, out var err, action, "bluetooth"))
        {
            return (true, string.Empty);
        }

        return (false, FirstNonEmpty(err, "rfkill unavailable"));
    });

    // ---- TCP connections ----

    public bool TryGetTcpConnections(out List<TcpConnectionInfo> connections)
    {
        connections = new List<TcpConnectionInfo>();
        var inodeToPid = BuildInodeToPidMap();

        var any = ReadProcNetTcp("/proc/net/tcp", isV6: false, connections, inodeToPid);
        var any6 = ReadProcNetTcp("/proc/net/tcp6", isV6: true, connections, inodeToPid);
        return any || any6;
    }

    private static bool ReadProcNetTcp(string path, bool isV6, List<TcpConnectionInfo> output, Dictionary<long, int> inodeToPid)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        try
        {
            var first = true;
            foreach (var line in File.ReadLines(path))
            {
                if (first)
                {
                    first = false; // header row
                    continue;
                }

                var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
                if (fields.Length < 10)
                {
                    continue;
                }

                var remote = fields[2];
                var colon = remote.IndexOf(':');
                if (colon < 0)
                {
                    continue;
                }

                var addrHex = remote[..colon];
                var portHex = remote[(colon + 1)..];
                if (!TryParseHexPort(portHex, out var port))
                {
                    continue;
                }

                var address = isV6 ? ParseHexIpv6(addrHex) : ParseHexIpv4(addrHex);
                if (address is null)
                {
                    continue;
                }

                var state = MapState(fields[3]);
                var pid = 0;
                if (long.TryParse(fields[9], out var inode) && inodeToPid.TryGetValue(inode, out var owner))
                {
                    pid = owner;
                }

                output.Add(new TcpConnectionInfo(address, port, state, pid));
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static IPAddress? ParseHexIpv4(string hex)
    {
        if (hex.Length != 8 || !uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
        {
            return null;
        }

        // /proc stores the address in host (little-endian) order; BitConverter on an LE machine
        // turns it straight back into network-order bytes.
        return new IPAddress(BitConverter.GetBytes(value));
    }

    private static IPAddress? ParseHexIpv6(string hex)
    {
        if (hex.Length != 32)
        {
            return null;
        }

        try
        {
            var bytes = new byte[16];
            for (var word = 0; word < 4; word++)
            {
                var chunk = hex.Substring(word * 8, 8);
                var value = uint.Parse(chunk, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                Array.Copy(BitConverter.GetBytes(value), 0, bytes, word * 4, 4);
            }

            return new IPAddress(bytes);
        }
        catch
        {
            return null;
        }
    }

    private static bool TryParseHexPort(string hex, out int port) =>
        int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out port);

    private static TcpState MapState(string stHex) => stHex switch
    {
        "01" => TcpState.Established,
        "02" => TcpState.SynSent,
        "03" => TcpState.SynReceived,
        "0A" => TcpState.Listen,
        _ => TcpState.Unknown
    };

    /// <summary>Maps each socket inode to the pid that owns it by scanning /proc/&lt;pid&gt;/fd.</summary>
    private static Dictionary<long, int> BuildInodeToPidMap()
    {
        var map = new Dictionary<long, int>();
        IEnumerable<string> pidDirs;
        try
        {
            pidDirs = Directory.EnumerateDirectories("/proc");
        }
        catch
        {
            return map;
        }

        foreach (var dir in pidDirs)
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid))
            {
                continue;
            }

            string[] fds;
            try
            {
                fds = Directory.GetFiles($"/proc/{pid}/fd");
            }
            catch
            {
                continue; // not our process / vanished
            }

            foreach (var fd in fds)
            {
                try
                {
                    var target = new FileInfo(fd).LinkTarget;
                    if (target is null || !target.StartsWith("socket:[", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var inodeText = target[8..^1]; // strip "socket:[" and "]"
                    if (long.TryParse(inodeText, out var inode))
                    {
                        map[inode] = pid;
                    }
                }
                catch
                {
                    // fd vanished or unreadable; skip.
                }
            }
        }

        return map;
    }

    // ---- DNS cache ----

    public IEnumerable<string> GetDnsCacheHosts()
    {
        // systemd-resolved offers no enumerable per-name cache comparable to Windows' DNS client
        // cache, so the Linux client relies on the live-TCP shield (blocklist resolved to IPs)
        // instead. Returning empty keeps DnsCacheMonitor a harmless no-op here.
        return Array.Empty<string>();
    }

    // ---- Processes ----

    public IReadOnlyList<ProcessInfo> GetProcessList()
    {
        var list = new List<ProcessInfo>();
        IEnumerable<string> dirs;
        try
        {
            dirs = Directory.EnumerateDirectories("/proc");
        }
        catch
        {
            return list;
        }

        foreach (var dir in dirs)
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid))
            {
                continue;
            }

            var name = ReadBareName(pid);
            if (name.Length > 0)
            {
                list.Add(new ProcessInfo(pid, name, null, null));
            }
        }

        return list;
    }

    public ProcessInfo? TryGetProcess(int pid)
    {
        var name = ReadBareName(pid);
        if (name.Length == 0)
        {
            return null;
        }

        return new ProcessInfo(pid, name, ReadExePath(pid), ReadCmdline(pid));
    }

    private static string ReadBareName(int pid)
    {
        // Prefer argv0's basename (full name); comm is truncated to 15 chars by the kernel.
        var cmdline = ReadCmdline(pid);
        if (!string.IsNullOrWhiteSpace(cmdline))
        {
            var argv0 = cmdline.Split(' ', 2)[0];
            var bare = ProcessNames.Bare(argv0);
            if (bare.Length > 0)
            {
                return bare;
            }
        }

        try
        {
            var comm = File.ReadAllText($"/proc/{pid}/comm").Trim();
            return ProcessNames.Bare(comm);
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string? ReadExePath(int pid)
    {
        try
        {
            return new FileInfo($"/proc/{pid}/exe").LinkTarget;
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadCmdline(int pid)
    {
        try
        {
            var raw = File.ReadAllBytes($"/proc/{pid}/cmdline");
            if (raw.Length == 0)
            {
                return null;
            }

            // Arguments are NUL-separated; turn them into a normal space-separated command line.
            return Encoding.UTF8.GetString(raw).Replace('\0', ' ').Trim();
        }
        catch
        {
            return null;
        }
    }

    // ---- Audio ----

    public bool TrySetVolume(int percent)
    {
        var level = Math.Clamp(percent, 0, 100);
        Shell.Run("pactl", "set-sink-mute", "@DEFAULT_SINK@", "0");
        if (Shell.Run("pactl", "set-sink-volume", "@DEFAULT_SINK@", $"{level}%"))
        {
            return true;
        }

        return Shell.Run("amixer", "-q", "sset", "Master", $"{level}%", "unmute");
    }

    public void Beep(int frequencyHz, int durationMs)
    {
        try
        {
            var wav = EnsureToneWav(frequencyHz, durationMs);
            if (wav is null)
            {
                return;
            }

            // Play and block for the tone's length so the alarm cadence matches Windows' Console.Beep.
            if (!Shell.Run("paplay", wav) && !Shell.Run("pw-play", wav))
            {
                Shell.Run("aplay", "-q", wav);
            }
        }
        catch
        {
            // Best-effort: a machine with no audio tools simply stays silent.
        }
    }

    private static string? EnsureToneWav(int frequencyHz, int durationMs)
    {
        try
        {
            var path = Path.Combine(Path.GetTempPath(), $"examlock_tone_{frequencyHz}_{durationMs}.wav");
            if (!File.Exists(path))
            {
                File.WriteAllBytes(path, BuildSineWav(frequencyHz, durationMs));
            }

            return path;
        }
        catch
        {
            return null;
        }
    }

    private static byte[] BuildSineWav(int frequencyHz, int durationMs)
    {
        const int sampleRate = 16000;
        const short amplitude = 12000;
        var sampleCount = sampleRate * durationMs / 1000;
        var dataSize = sampleCount * 2; // 16-bit mono

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);

        writer.Write(Encoding.ASCII.GetBytes("RIFF"));
        writer.Write(36 + dataSize);
        writer.Write(Encoding.ASCII.GetBytes("WAVE"));
        writer.Write(Encoding.ASCII.GetBytes("fmt "));
        writer.Write(16);                 // PCM chunk size
        writer.Write((short)1);           // PCM
        writer.Write((short)1);           // mono
        writer.Write(sampleRate);
        writer.Write(sampleRate * 2);     // byte rate
        writer.Write((short)2);           // block align
        writer.Write((short)16);          // bits per sample
        writer.Write(Encoding.ASCII.GetBytes("data"));
        writer.Write(dataSize);

        for (var i = 0; i < sampleCount; i++)
        {
            var sample = (short)(amplitude * Math.Sin(2 * Math.PI * frequencyHz * i / sampleRate));
            writer.Write(sample);
        }

        writer.Flush();
        return stream.ToArray();
    }

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? string.Empty;
}
