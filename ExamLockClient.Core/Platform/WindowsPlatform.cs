using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ExamLockClient.Core.Platform;

/// <summary>
/// Windows backend. Mirrors the techniques of the original WinForms client: netsh for the Wi-Fi
/// adapter, the IP Helper API for connection ownership, WMI for command lines and the DNS cache,
/// and Core Audio for the alarm volume.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPlatform : IPlatform
{
    public string Name => "Windows";

    public string WifiAdapterName { get; set; } = "Wi-Fi";

    public bool IsElevated
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
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
            var psi = new ProcessStartInfo
            {
                FileName = executablePath,
                WorkingDirectory = Environment.CurrentDirectory,
                UseShellExecute = true,
                Verb = "runas"
            };

            foreach (var arg in args)
            {
                psi.ArgumentList.Add(arg);
            }

            Process.Start(psi);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return false; // user declined the UAC prompt
        }
        catch
        {
            return false;
        }
    }

    // ---- Radios ----

    public bool DisableWifi(out string error) =>
        RunNetsh($"interface set interface name=\"{WifiAdapterName}\" admin=disabled", out error);

    public bool EnableWifi(out string error) =>
        RunNetsh($"interface set interface name=\"{WifiAdapterName}\" admin=enabled", out error);

    public Task<(bool ok, string error)> SetBluetoothAsync(bool on) =>
        // The WinRT Radios API needs the windows-specific TFM; this net8.0 client keeps Bluetooth
        // as a no-op and leans on the AI shield. The dedicated WinForms client still toggles it.
        Task.FromResult((false, "Bluetooth toggle is handled by the Windows-only client."));

    private static bool RunNetsh(string args, out string error)
    {
        error = string.Empty;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                error = "Failed to start netsh.";
                return false;
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    // ---- TCP connections (IP Helper, owner pid) ----

    public bool TryGetTcpConnections(out List<TcpConnectionInfo> connections)
    {
        connections = new List<TcpConnectionInfo>();
        var ok4 = TryReadTcpTable(connections, AfInet);
        var ok6 = TryReadTcpTable(connections, AfInet6);
        return ok4 || ok6;
    }

    private static bool TryReadTcpTable(List<TcpConnectionInfo> connections, int family)
    {
        var bufferSize = 0;
        var result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, family, TcpTableOwnerPidAll, 0);
        if (result is not ErrorInsufficientBuffer and not NoError || bufferSize < sizeof(int))
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            result = GetExtendedTcpTable(buffer, ref bufferSize, true, family, TcpTableOwnerPidAll, 0);
            if (result != NoError)
            {
                return false;
            }

            var rows = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));

            if (family == AfInet)
            {
                var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                for (var i = 0; i < rows; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                    connections.Add(new TcpConnectionInfo(
                        new IPAddress(BitConverter.GetBytes(row.RemoteAddr)),
                        ReadPort(row.RemotePort),
                        ToTcpState(row.State),
                        (int)row.OwningPid));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }
            else
            {
                var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                for (var i = 0; i < rows; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                    connections.Add(new TcpConnectionInfo(
                        new IPAddress(row.RemoteAddr, row.RemoteScopeId),
                        ReadPort(row.RemotePort),
                        ToTcpState(row.State),
                        (int)row.OwningPid));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
            }

            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ReadPort(byte[] bytes) => (bytes[0] << 8) + bytes[1];

    private static TcpState ToTcpState(uint state) =>
        Enum.IsDefined(typeof(TcpState), (int)state) ? (TcpState)state : TcpState.Unknown;

    // ---- DNS cache (WMI) ----

    public IEnumerable<string> GetDnsCacheHosts()
    {
        var hosts = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\StandardCimv2", "SELECT Entry, Name, Data FROM MSFT_DNSClientCache");
            using var results = searcher.Get();
            foreach (var obj in results)
            {
                Add(hosts, obj["Entry"] as string);
                Add(hosts, obj["Name"] as string);
                Add(hosts, obj["Data"] as string);
            }
        }
        catch
        {
            // WMI/DNS cache unavailable: report nothing this round.
        }

        return hosts;

        static void Add(List<string> list, string? host)
        {
            if (!string.IsNullOrWhiteSpace(host))
            {
                list.Add(host);
            }
        }
    }

    // ---- Processes ----

    public IReadOnlyList<ProcessInfo> GetProcessList()
    {
        var list = new List<ProcessInfo>();
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    list.Add(new ProcessInfo(process.Id, ProcessNames.Bare(process.ProcessName), null, null));
                }
                catch
                {
                    // Process vanished between enumeration and access.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
        catch
        {
            // Transient enumeration failure; caller retries next tick.
        }

        return list;
    }

    public ProcessInfo? TryGetProcess(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return new ProcessInfo(
                pid,
                ProcessNames.Bare(process.ProcessName),
                SafePath(process),
                SafeCommandLine(pid));
        }
        catch
        {
            return null;
        }
    }

    private static string? SafePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static string? SafeCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + pid);
            using var results = searcher.Get();
            foreach (var obj in results)
            {
                return obj["CommandLine"] as string;
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    // ---- Audio ----

    public void Beep(int frequencyHz, int durationMs)
    {
        try
        {
            Console.Beep(frequencyHz, durationMs);
        }
        catch
        {
            // Console.Beep can fail on some configurations; ignore.
        }
    }

    public bool TrySetVolume(int percent)
    {
        IMMDeviceEnumerator? enumerator = null;
        IMMDevice? device = null;
        IAudioEndpointVolume? volume = null;
        try
        {
            enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
            if (enumerator.GetDefaultAudioEndpoint(0, 1, out device) != 0 || device is null)
            {
                return false;
            }

            var iid = typeof(IAudioEndpointVolume).GUID;
            if (device.Activate(ref iid, 1, IntPtr.Zero, out var obj) != 0 || obj is not IAudioEndpointVolume v)
            {
                return false;
            }

            volume = v;
            var ctx = Guid.Empty;
            volume.SetMute(false, ref ctx);
            return volume.SetMasterVolumeLevelScalar(Math.Clamp(percent, 0, 100) / 100f, ref ctx) == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (volume is not null) Marshal.ReleaseComObject(volume);
            if (device is not null) Marshal.ReleaseComObject(device);
            if (enumerator is not null) Marshal.ReleaseComObject(enumerator);
        }
    }

    // ---- Native interop ----

    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] LocalPort;
        public uint RemoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
        public uint RemoteScopeId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumerator
    {
    }

    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        [PreserveSig] int EnumAudioEndpoints(int dataFlow, int stateMask, out IntPtr devices);
        [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice? device);
    }

    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        [PreserveSig] int Activate(ref Guid iid, int clsCtx, IntPtr activationParams,
            [MarshalAs(UnmanagedType.IUnknown)] out object iface);
    }

    [ComImport, Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioEndpointVolume
    {
        [PreserveSig] int RegisterControlChangeNotify(IntPtr notify);
        [PreserveSig] int UnregisterControlChangeNotify(IntPtr notify);
        [PreserveSig] int GetChannelCount(out int count);
        [PreserveSig] int SetMasterVolumeLevel(float levelDb, ref Guid eventContext);
        [PreserveSig] int SetMasterVolumeLevelScalar(float level, ref Guid eventContext);
        [PreserveSig] int GetMasterVolumeLevel(out float levelDb);
        [PreserveSig] int GetMasterVolumeLevelScalar(out float level);
        [PreserveSig] int SetChannelVolumeLevel(uint channel, float levelDb, ref Guid ctx);
        [PreserveSig] int SetChannelVolumeLevelScalar(uint channel, float level, ref Guid ctx);
        [PreserveSig] int GetChannelVolumeLevel(uint channel, out float levelDb);
        [PreserveSig] int GetChannelVolumeLevelScalar(uint channel, out float level);
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool mute, ref Guid eventContext);
    }
}
