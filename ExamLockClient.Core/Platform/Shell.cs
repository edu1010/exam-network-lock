using System.Diagnostics;

namespace ExamLockClient.Core.Platform;

/// <summary>Tiny helper to run an external command and capture its result. Never throws.</summary>
internal static class Shell
{
    // Desktop users usually lack /usr/sbin in PATH, yet tools such as rfkill live there and work
    // unprivileged through the session's device ACL (uaccess).
    private static readonly string[] ExtraDirs = { "/usr/sbin", "/sbin", "/usr/bin", "/bin" };

    public static bool Run(string file, params string[] args) => Run(file, out _, out _, args);

    /// <summary>Full path for a bare command name, searching PATH plus the sbin directories.</summary>
    public static string Resolve(string file)
    {
        if (file.Contains('/') || OperatingSystem.IsWindows())
        {
            return file;
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in path.Split(':', StringSplitOptions.RemoveEmptyEntries).Concat(ExtraDirs))
        {
            var candidate = System.IO.Path.Combine(dir, file);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return file;
    }

    // A tool waiting on a missing daemon (bluetoothctl without bluetoothd) must not hang the client.
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    public static bool Run(string file, out string stdout, out string stderr, params string[] args) =>
        Run(file, DefaultTimeout, out stdout, out stderr, args);

    public static bool Run(string file, TimeSpan timeout, out string stdout, out string stderr, params string[] args)
    {
        stdout = string.Empty;
        stderr = string.Empty;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Resolve(file),
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            foreach (var arg in args)
            {
                psi.ArgumentList.Add(arg);
            }

            using var process = Process.Start(psi);
            if (process is null)
            {
                stderr = $"Failed to start {file}.";
                return false;
            }

            // Interactive tools (bluetoothctl) would otherwise wait for commands on stdin.
            process.StandardInput.Close();

            // Drain both pipes concurrently: a full stderr pipe must not block stdout forever.
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeout))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Already gone.
                }

                stderr = $"{file} timed out.";
                return false;
            }

            process.WaitForExit();
            stdout = outputTask.GetAwaiter().GetResult();
            stderr = errorTask.GetAwaiter().GetResult();
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            stderr = ex.Message;
            return false;
        }
    }
}
