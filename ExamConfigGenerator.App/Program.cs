using ExamDesktop.Ui;

namespace ExamConfigGenerator;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args) => DesktopApp.Run(args, () => new MainWindow());
}
