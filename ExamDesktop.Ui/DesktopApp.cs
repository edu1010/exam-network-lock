using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;

namespace ExamDesktop.Ui;

/// <summary>Code-only Avalonia application: Fluent light theme plus the window supplied by each app.</summary>
public sealed class DesktopApp : Application
{
    private static Func<Window>? _createMainWindow;

    /// <summary>Starts the desktop lifetime with <paramref name="createMainWindow"/> as the main window.</summary>
    public static int Run(string[] args, Func<Window> createMainWindow)
    {
        _createMainWindow = createMainWindow;
        return AppBuilder.Configure<DesktopApp>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace()
            .StartWithClassicDesktopLifetime(args);
    }

    public override void Initialize()
    {
        RequestedThemeVariant = ThemeVariant.Light;
        Styles.Add(new FluentTheme());
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop && _createMainWindow is not null)
        {
            desktop.MainWindow = _createMainWindow();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
