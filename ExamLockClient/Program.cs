using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace ExamLockClient;

internal static class Program
{
    internal static string? StartupConfigPath { get; private set; }

    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        StartupConfigPath = ParseStartupConfigPath(Environment.GetCommandLineArgs());

        if (!EnsureAdministrator())
        {
            return;
        }

        Application.Run(new MainForm());
    }

    private static bool EnsureAdministrator()
    {
        if (IsAdministrator())
        {
            return true;
        }

        var result = MessageBox.Show(
            Lang.T("adminPrompt"),
            Lang.T("adminTitle"),
            MessageBoxButtons.OKCancel,
            MessageBoxIcon.Warning);

        if (result != DialogResult.OK)
        {
            return true;
        }

        return TryRelaunchAsAdministrator() ? false : true;
    }

    internal static bool TryRelaunchAsAdministrator(IWin32Window? owner = null, string? configPath = null)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Application.ExecutablePath,
                WorkingDirectory = Environment.CurrentDirectory,
                UseShellExecute = true,
                Verb = "runas"
            };

            foreach (var arg in Environment.GetCommandLineArgs().Skip(1))
            {
                psi.ArgumentList.Add(arg);
            }

            if (!string.IsNullOrWhiteSpace(configPath))
            {
                psi.ArgumentList.Add("--config");
                psi.ArgumentList.Add(configPath);
            }

            Process.Start(psi);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return false;
        }
        catch
        {
            MessageBox.Show(
                owner,
                Lang.T("adminRelaunchFail"),
                Lang.T("adminTitle"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return false;
        }
    }

    internal static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static string? ParseStartupConfigPath(string[] args)
    {
        string? configPath = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--config", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                configPath = args[++i];
            }
        }

        return configPath;
    }
}
