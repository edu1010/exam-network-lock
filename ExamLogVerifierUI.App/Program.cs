using ExamDesktop.Ui;

namespace ExamLogVerifierUI;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args) => DesktopApp.Run(args, () => new MainWindow(args));
}
