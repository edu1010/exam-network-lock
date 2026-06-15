using System.Drawing.Drawing2D;

namespace ExamLockClient;

/// <summary>
/// A large, GDI+-drawn shield that shows the protection state at a glance, readable
/// from across the classroom: green/✓ protected, amber/! attention, red/✕ danger.
/// </summary>
public sealed class ShieldControl : Control
{
    public enum ShieldStatus
    {
        Idle,
        Green,
        Yellow,
        Red
    }

    private ShieldStatus _status = ShieldStatus.Idle;
    private string _caption = "";

    public ShieldControl()
    {
        DoubleBuffered = true;
        SetStyle(ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
        BackColor = Theme.Background;
    }

    public ShieldStatus Status
    {
        get => _status;
        set
        {
            if (_status != value)
            {
                _status = value;
                Invalidate();
            }
        }
    }

    public string Caption
    {
        get => _caption;
        set
        {
            _caption = value ?? "";
            Invalidate();
        }
    }

    private (Color color, string glyph) Visuals() => _status switch
    {
        ShieldStatus.Green => (Theme.Green, "✓"),  // ✓
        ShieldStatus.Yellow => (Theme.Amber, "!"),
        ShieldStatus.Red => (Theme.Red, "✕"),       // ✕
        _ => (Theme.Idle, "⋯")                      // ⋯
    };

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        g.Clear(BackColor);

        var (color, glyph) = Visuals();

        // Shield bounding box: centered, leaving room for the caption below.
        float captionH = 34f;
        float availH = Height - captionH - 16;
        float shieldH = Math.Max(40f, Math.Min(availH, Width * 0.62f));
        float shieldW = shieldH * 0.82f;
        float ox = (Width - shieldW) / 2f;
        float oy = 8f;

        using var path = BuildShieldPath(ox, oy, shieldW, shieldH);

        // Soft drop shadow.
        using (var shadow = new SolidBrush(Color.FromArgb(40, 0, 0, 0)))
        {
            var state = g.Save();
            g.TranslateTransform(0, 3);
            g.FillPath(shadow, path);
            g.Restore(state);
        }

        // Gradient fill.
        using (var brush = new LinearGradientBrush(
                   new RectangleF(ox, oy, shieldW, shieldH),
                   Lighten(color, 0.18f), color, LinearGradientMode.Vertical))
        {
            g.FillPath(brush, path);
        }

        using (var pen = new Pen(Darken(color, 0.15f), 2f))
        {
            g.DrawPath(pen, path);
        }

        // Glyph centered in the upper part of the shield.
        var glyphRect = new RectangleF(ox, oy + shieldH * 0.06f, shieldW, shieldH * 0.66f);
        using (var glyphFont = new Font("Segoe UI", shieldH * 0.34f, FontStyle.Bold, GraphicsUnit.Pixel))
        using (var white = new SolidBrush(Color.White))
        using (var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
        {
            g.DrawString(glyph, glyphFont, white, glyphRect, fmt);
        }

        // Caption below the shield.
        var captionRect = new RectangleF(0, Height - captionH - 2, Width, captionH);
        using (var captionFont = new Font("Segoe UI Semibold", 15f))
        using (var brush = new SolidBrush(color))
        using (var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
        {
            g.DrawString(_caption, captionFont, brush, captionRect, fmt);
        }
    }

    private static GraphicsPath BuildShieldPath(float ox, float oy, float w, float h)
    {
        var path = new GraphicsPath();
        float left = ox;
        float right = ox + w;
        float top = oy;
        float midX = ox + w / 2f;
        float bottom = oy + h;
        float r = w * 0.14f;
        float shoulderY = top + h * 0.60f;

        path.AddArc(left, top, r * 2, r * 2, 180, 90);            // top-left corner
        path.AddArc(right - r * 2, top, r * 2, r * 2, 270, 90);   // top-right corner
        path.AddLine(right, top + r, right, shoulderY);           // right edge
        path.AddBezier(                                           // right shoulder -> bottom tip
            right, shoulderY,
            right, bottom - h * 0.14f,
            midX + w * 0.20f, bottom - h * 0.03f,
            midX, bottom);
        path.AddBezier(                                           // bottom tip -> left shoulder
            midX, bottom,
            midX - w * 0.20f, bottom - h * 0.03f,
            left, bottom - h * 0.14f,
            left, shoulderY);
        path.AddLine(left, shoulderY, left, top + r);             // left edge
        path.CloseFigure();
        return path;
    }

    private static Color Lighten(Color c, float amount) => Color.FromArgb(
        c.A,
        (int)Math.Min(255, c.R + 255 * amount),
        (int)Math.Min(255, c.G + 255 * amount),
        (int)Math.Min(255, c.B + 255 * amount));

    private static Color Darken(Color c, float amount) => Color.FromArgb(
        c.A,
        (int)Math.Max(0, c.R - 255 * amount),
        (int)Math.Max(0, c.G - 255 * amount),
        (int)Math.Max(0, c.B - 255 * amount));
}
