using System.Diagnostics;
using System.Text;

namespace ExamLockClient;

public sealed class NetworkAdapterService
{
    public string AdapterName { get; set; } = "Wi-Fi";

    public bool DisableWifi(out string error)
    {
        return RunNetsh($"interface set interface name=\"{AdapterName}\" admin=disabled", out error);
    }

    public bool EnableWifi(out string error)
    {
        return RunNetsh($"interface set interface name=\"{AdapterName}\" admin=enabled", out error);
    }

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
}
