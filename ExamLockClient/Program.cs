namespace ExamLockClient;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        if (!EnsureAdministrator())
        {
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    private static bool EnsureAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                return true;
            }

            var result = MessageBox.Show(
                "This app needs administrator permissions to disable Wi-Fi. Relaunch as administrator?",
                "Administrator Required",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result != DialogResult.Yes)
            {
                return true;
            }

            var exePath = Application.ExecutablePath;
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                Verb = "runas"
            };
            System.Diagnostics.Process.Start(psi);
            return false;
        }
        catch
        {
            return true;
        }
    }
}
