using System.Security.Cryptography;
using System.Text;
using ExamShared;

namespace ExamConfigGenerator;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
