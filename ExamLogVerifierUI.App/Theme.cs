namespace ExamLogVerifierUI;

/// <summary>
/// Colour table expected by the shared EventCatalog (System.Drawing colours, converted to Avalonia
/// brushes with <c>Palette.ToBrush</c>). Values match the WinForms Theme.
/// </summary>
internal static class Theme
{
    public static readonly Color Surface = Color.White;
    public static readonly Color TextMuted = Color.FromArgb(107, 114, 128);

    public static readonly Color GreenText = Color.FromArgb(21, 128, 61);
    public static readonly Color GreenBg = Color.FromArgb(223, 246, 232);
    public static readonly Color AmberText = Color.FromArgb(180, 83, 9);
    public static readonly Color AmberBg = Color.FromArgb(254, 243, 214);
    public static readonly Color RedText = Color.FromArgb(185, 28, 28);
    public static readonly Color RedBg = Color.FromArgb(253, 226, 226);
    public static readonly Color InfoBg = Color.FromArgb(240, 242, 245);
}
