namespace ExamConfigGenerator;

/// <summary>Light, modern palette and small styling helpers for the generator UI.</summary>
internal static class Theme
{
    public static readonly Color Background = Color.FromArgb(245, 246, 248);
    public static readonly Color Surface = Color.White;
    public static readonly Color Border = Color.FromArgb(209, 213, 219);
    public static readonly Color Text = Color.FromArgb(31, 41, 55);
    public static readonly Color TextMuted = Color.FromArgb(107, 114, 128);
    public static readonly Color Accent = Color.FromArgb(37, 99, 235);
    public static readonly Color AccentHover = Color.FromArgb(29, 78, 216);

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
        button.Height = Math.Max(button.Height, 34);
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

    public static void StyleInput(TextBox box)
    {
        box.BorderStyle = BorderStyle.FixedSingle;
        box.BackColor = Surface;
        box.ForeColor = Text;
        box.Font = Base;
    }

    public static void StyleList(ListBox list)
    {
        list.BorderStyle = BorderStyle.FixedSingle;
        list.BackColor = Surface;
        list.ForeColor = Text;
        list.Font = Base;
        list.IntegralHeight = false;
    }

    public static GroupBox Section(string title)
    {
        return new GroupBox
        {
            Text = title,
            Font = Heading,
            ForeColor = Text,
            BackColor = Background,
            Padding = new Padding(12, 8, 12, 12),
            Margin = new Padding(0, 0, 0, 14),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink
        };
    }
}
