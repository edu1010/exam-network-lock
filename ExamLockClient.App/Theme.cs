using Avalonia.Media;

namespace ExamLockClient.App;

/// <summary>Light, modern palette shared across the client UI (Avalonia colours/brushes).</summary>
internal static class Palette
{
    public static readonly Color Background = Color.FromRgb(245, 246, 248);
    public static readonly Color Surface = Colors.White;
    public static readonly Color Border = Color.FromRgb(209, 213, 219);
    public static readonly Color Text = Color.FromRgb(31, 41, 55);
    public static readonly Color TextMuted = Color.FromRgb(107, 114, 128);
    public static readonly Color Accent = Color.FromRgb(37, 99, 235);
    public static readonly Color AccentHover = Color.FromRgb(29, 78, 216);

    public static readonly Color Green = Color.FromRgb(22, 163, 74);
    public static readonly Color Amber = Color.FromRgb(217, 119, 6);
    public static readonly Color Red = Color.FromRgb(220, 38, 38);
    public static readonly Color Idle = Color.FromRgb(148, 163, 184);

    public static readonly IBrush BackgroundBrush = new SolidColorBrush(Background);
    public static readonly IBrush SurfaceBrush = new SolidColorBrush(Surface);
    public static readonly IBrush BorderBrush = new SolidColorBrush(Border);
    public static readonly IBrush TextBrush = new SolidColorBrush(Text);
    public static readonly IBrush TextMutedBrush = new SolidColorBrush(TextMuted);
    public static readonly IBrush AccentBrush = new SolidColorBrush(Accent);

    public const string FontFamily = "Inter, Segoe UI, sans-serif";
}
