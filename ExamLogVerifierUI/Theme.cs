namespace ExamLogVerifierUI;

/// <summary>Light, modern palette and styling helpers for the verifier UI. Shares the generator's
/// base palette and adds status/severity tints plus a flat <see cref="DataGridView"/> styler.</summary>
internal static class Theme
{
    public static readonly Color Background = Color.FromArgb(245, 246, 248);
    public static readonly Color Surface = Color.White;
    public static readonly Color Border = Color.FromArgb(224, 227, 232);
    public static readonly Color Text = Color.FromArgb(31, 41, 55);
    public static readonly Color TextMuted = Color.FromArgb(107, 114, 128);
    public static readonly Color Accent = Color.FromArgb(37, 99, 235);
    public static readonly Color AccentHover = Color.FromArgb(29, 78, 216);
    public static readonly Color SelectionBg = Color.FromArgb(224, 234, 255);

    // Status / severity — text colors (saturated) and matching light "pastel" backgrounds.
    public static readonly Color GreenText = Color.FromArgb(21, 128, 61);
    public static readonly Color GreenBg = Color.FromArgb(223, 246, 232);
    public static readonly Color AmberText = Color.FromArgb(180, 83, 9);
    public static readonly Color AmberBg = Color.FromArgb(254, 243, 214);
    public static readonly Color RedText = Color.FromArgb(185, 28, 28);
    public static readonly Color RedBg = Color.FromArgb(253, 226, 226);
    public static readonly Color InfoBg = Color.FromArgb(240, 242, 245);

    public static readonly Font Base = new("Segoe UI", 9.75f);
    public static readonly Font Bold = new("Segoe UI Semibold", 9.75f);
    public static readonly Font Heading = new("Segoe UI Semibold", 11f);
    public static readonly Font Mono = new("Consolas", 9f);

    public static void StylePrimary(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.BackColor = Accent;
        button.ForeColor = Color.White;
        button.Font = Bold;
        button.Cursor = Cursors.Hand;
        button.FlatAppearance.MouseOverBackColor = AccentHover;
        button.Height = Math.Max(button.Height, 32);
        button.Padding = new Padding(10, 4, 10, 4);
        button.AutoSize = true;
    }

    public static void StyleSecondary(Button button)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderColor = Color.FromArgb(209, 213, 219);
        button.FlatAppearance.BorderSize = 1;
        button.BackColor = Surface;
        button.ForeColor = Text;
        button.Font = Base;
        button.Cursor = Cursors.Hand;
        button.Height = Math.Max(button.Height, 32);
        button.Padding = new Padding(10, 4, 10, 4);
        button.AutoSize = true;
    }

    public static void StyleCombo(ComboBox combo)
    {
        combo.DropDownStyle = ComboBoxStyle.DropDownList;
        combo.FlatStyle = FlatStyle.Flat;
        combo.BackColor = Surface;
        combo.ForeColor = Text;
        combo.Font = Base;
    }

    public static void StyleGrid(DataGridView grid)
    {
        grid.BackgroundColor = Surface;
        grid.BorderStyle = BorderStyle.None;
        grid.EnableHeadersVisualStyles = false;
        grid.ColumnHeadersDefaultCellStyle.BackColor = Background;
        grid.ColumnHeadersDefaultCellStyle.ForeColor = TextMuted;
        grid.ColumnHeadersDefaultCellStyle.Font = Bold;
        grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(6, 0, 6, 0);
        grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        grid.ColumnHeadersHeight = 34;
        grid.RowHeadersVisible = false;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.ReadOnly = true;
        grid.MultiSelect = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        grid.GridColor = Border;
        grid.DefaultCellStyle.BackColor = Surface;
        grid.DefaultCellStyle.ForeColor = Text;
        grid.DefaultCellStyle.SelectionBackColor = SelectionBg;
        grid.DefaultCellStyle.SelectionForeColor = Text;
        grid.DefaultCellStyle.Font = Base;
        grid.DefaultCellStyle.Padding = new Padding(6, 4, 6, 4);
        grid.RowTemplate.Height = 30;
        grid.AllowUserToResizeColumns = true;
        grid.Font = Base;
        grid.ScrollBars = ScrollBars.Both;
    }
}
