namespace ExamLockClient.Core.Platform;

/// <summary>Picks the backend for the OS the client is running on.</summary>
public static class PlatformFactory
{
    private static IPlatform? _current;

    public static IPlatform Current => _current ??= Create();

    private static IPlatform Create()
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsPlatform();
        }

        if (OperatingSystem.IsLinux())
        {
            return new LinuxPlatform();
        }

        // macOS or anything else: fall back to the Linux backend, which relies on POSIX-ish tools
        // and /proc-style discovery. Radios/DNS will simply report "unsupported" there.
        return new LinuxPlatform();
    }
}
