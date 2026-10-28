using Avalonia.Media;

namespace ExamDesktop.Ui;

/// <summary>Light palette shared by the teacher apps; matches the WinForms Theme colours.</summary>
public static class Palette
{
    public static readonly IBrush Background = Brush(245, 246, 248);
    public static readonly IBrush Surface = Brushes.White;
    public static readonly IBrush Border = Brush(209, 213, 219);
    public static readonly IBrush Text = Brush(31, 41, 55);
    public static readonly IBrush TextMuted = Brush(107, 114, 128);
    public static readonly IBrush Accent = Brush(37, 99, 235);

    public static readonly IBrush GreenText = Brush(21, 128, 61);
    public static readonly IBrush AmberText = Brush(180, 83, 9);
    public static readonly IBrush RedText = Brush(185, 28, 28);

    public static IBrush Brush(byte r, byte g, byte b) => new SolidColorBrush(Color.FromRgb(r, g, b));

    /// <summary>Converts a System.Drawing colour (used by the shared WinForms-era tables) to a brush.</summary>
    public static IBrush ToBrush(this System.Drawing.Color c) => new SolidColorBrush(Color.FromArgb(c.A, c.R, c.G, c.B));

    public static System.Drawing.Color Darken(this System.Drawing.Color c, double f) =>
        System.Drawing.Color.FromArgb(c.A,
            (int)Math.Max(0, c.R * (1 - f)),
            (int)Math.Max(0, c.G * (1 - f)),
            (int)Math.Max(0, c.B * (1 - f)));
}
