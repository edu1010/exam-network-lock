using Avalonia;

namespace ExamLockClient.App;

internal static class Program
{
    /// <summary>Path passed with <c>--config &lt;path&gt;</c>, consumed by the main window on load.</summary>
    internal static string? StartupConfigPath { get; private set; }

    [STAThread]
    public static void Main(string[] args)
    {
        StartupConfigPath = ParseStartupConfigPath(args);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    private static string? ParseStartupConfigPath(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--config", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                return args[i + 1];
            }
        }

        return null;
    }
}
