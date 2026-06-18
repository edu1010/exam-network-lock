using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ExamLockClient;

internal sealed class TcpConnectionOwner
{
    public required IPAddress RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    public required TcpState State { get; init; }
    public int ProcessId { get; init; }
}

internal static class TcpConnectionOwnerTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;

    public static bool TryGetAll(out List<TcpConnectionOwner> connections)
    {
        connections = new List<TcpConnectionOwner>();
        var ok4 = TryReadIPv4(connections);
        var ok6 = TryReadIPv6(connections);
        return ok4 || ok6;
    }

    private static bool TryReadIPv4(List<TcpConnectionOwner> connections)
    {
        var bufferSize = 0;
        var result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref bufferSize,
            true,
            AfInet,
            TcpTableClass.TcpTableOwnerPidAll,
            0);

        if (result is not ErrorInsufficientBuffer and not NoError)
        {
            return false;
        }

        if (bufferSize < sizeof(int))
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            result = GetExtendedTcpTable(
                buffer,
                ref bufferSize,
                true,
                AfInet,
                TcpTableClass.TcpTableOwnerPidAll,
                0);

            if (result != NoError)
            {
                return false;
            }

            var rows = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (var i = 0; i < rows; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                connections.Add(new TcpConnectionOwner
                {
                    RemoteAddress = new IPAddress(BitConverter.GetBytes(row.RemoteAddr)),
                    RemotePort = ReadPort(row.RemotePort),
                    State = ToTcpState(row.State),
                    ProcessId = (int)row.OwningPid
                });
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }

            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryReadIPv6(List<TcpConnectionOwner> connections)
    {
        var bufferSize = 0;
        var result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref bufferSize,
            true,
            AfInet6,
            TcpTableClass.TcpTableOwnerPidAll,
            0);

        if (result is not ErrorInsufficientBuffer and not NoError)
        {
            return false;
        }

        if (bufferSize < sizeof(int))
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            result = GetExtendedTcpTable(
                buffer,
                ref bufferSize,
                true,
                AfInet6,
                TcpTableClass.TcpTableOwnerPidAll,
                0);

            if (result != NoError)
            {
                return false;
            }

            var rows = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();

            for (var i = 0; i < rows; i++)
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                connections.Add(new TcpConnectionOwner
                {
                    RemoteAddress = new IPAddress(row.RemoteAddr, row.RemoteScopeId),
                    RemotePort = ReadPort(row.RemotePort),
                    State = ToTcpState(row.State),
                    ProcessId = (int)row.OwningPid
                });
                rowPtr = IntPtr.Add(rowPtr, rowSize);
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

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TcpTableClass tblClass,
        uint reserved);

    private enum TcpTableClass
    {
        TcpTableBasicListener,
        TcpTableBasicConnections,
        TcpTableBasicAll,
        TcpTableOwnerPidListener,
        TcpTableOwnerPidConnections,
        TcpTableOwnerPidAll,
        TcpTableOwnerModuleListener,
        TcpTableOwnerModuleConnections,
        TcpTableOwnerModuleAll
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] LocalPort;

        public uint RemoteAddr;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] RemotePort;

        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;

        public uint LocalScopeId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;

        public uint RemoteScopeId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] RemotePort;

        public uint State;
        public uint OwningPid;
    }
}
