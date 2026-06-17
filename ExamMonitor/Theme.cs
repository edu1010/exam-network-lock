namespace ExamMonitor;

/// <summary>Light, modern palette and small styling helpers for the monitor UI.</summary>
internal static class Theme
{
    public static readonly Color Background = Color.FromArgb(245, 246, 248);
    public static readonly Color Surface = Color.White;
    public static readonly Color Border = Color.FromArgb(209, 213, 219);
    public static readonly Color Text = Color.FromArgb(31, 41, 55);
    public static readonly Color TextMuted = Color.FromArgb(107, 114, 128);
    public static readonly Color Accent = Color.FromArgb(37, 99, 235);
    public static readonly Color AccentHover = Color.FromArgb(29, 78, 216);

    public static readonly Color Green = Color.FromArgb(220, 245, 228);
    public static readonly Color Amber = Color.FromArgb(253, 240, 213);
    public static readonly Color Red = Color.FromArgb(253, 222, 222);
    public static readonly Color Idle = Color.FromArgb(238, 240, 243);

    public static readonly Font Base = new("Segoe UI", 9.75f);
    public static readonly Font Bold = new("Segoe UI Semibold", 9.75f);
    public static readonly Font Heading = new("Segoe UI Semibold", 11f);

    public static void StylePrimary(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.BackColor = Accent;
        button.ForeColor = Color.White;
        button.Font = Bold;
        button.Cursor = Cursors.Hand;
        button.FlatAppearance.MouseOverBackColor = AccentHover;
    }

    public static void StyleSecondary(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderColor = Border;
        button.FlatAppearance.BorderSize = 1;
        button.BackColor = Surface;
        button.ForeColor = Text;
        button.Font = Base;
        button.Cursor = Cursors.Hand;
    }
}
