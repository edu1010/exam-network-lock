using ExamDesktop.Ui;

namespace ExamMonitor;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args) => DesktopApp.Run(args, () => new MainWindow());
}
