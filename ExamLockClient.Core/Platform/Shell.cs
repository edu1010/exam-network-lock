using System.Diagnostics;

namespace ExamLockClient.Core.Platform;

/// <summary>Tiny helper to run an external command and capture its result. Never throws.</summary>
internal static class Shell
{
    public static bool Run(string file, params string[] args) => Run(file, out _, out _, args);

    public static bool Run(string file, out string stdout, out string stderr, params string[] args)
    {
        stdout = string.Empty;
        stderr = string.Empty;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                CreateNoWindow = true,
                UseShellExecute = false,
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

            stdout = process.StandardOutput.ReadToEnd();
            stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            stderr = ex.Message;
            return false;
        }
    }
}
