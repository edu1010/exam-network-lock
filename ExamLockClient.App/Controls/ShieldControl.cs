using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace ExamLockClient.App.Controls;

/// <summary>
/// A large, vector-drawn shield showing the protection state at a glance, readable from across the
/// classroom: green/✓ protected, amber/! attention, red/✕ danger. Avalonia port of the original
/// GDI+ control.
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

    public ShieldStatus Status
    {
        get => _status;
        set
        {
            if (_status != value)
            {
                _status = value;
                InvalidateVisual();
            }
        }
    }

    public string Caption
    {
        get => _caption;
        set
        {
            _caption = value ?? "";
            InvalidateVisual();
        }
    }

    private (Color color, string glyph) Visuals() => _status switch
    {
        ShieldStatus.Green => (Palette.Green, "✓"),
        ShieldStatus.Yellow => (Palette.Amber, "!"),
        ShieldStatus.Red => (Palette.Red, "✕"),
        _ => (Palette.Idle, "⋯")
    };

    public override void Render(DrawingContext context)
    {
        var width = Bounds.Width;
        var height = Bounds.Height;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        var (color, glyph) = Visuals();

        const double captionH = 34;
        var availH = height - captionH - 16;
        var shieldH = Math.Max(40, Math.Min(availH, width * 0.62));
        var shieldW = shieldH * 0.82;
        var ox = (width - shieldW) / 2;
        var oy = 8.0;

        var geometry = BuildShieldGeometry(ox, oy, shieldW, shieldH);

        var fill = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(Lighten(color, 0.18), 0),
                new GradientStop(color, 1)
            }
        };
        var pen = new Pen(new SolidColorBrush(Darken(color, 0.15)), 2);
        context.DrawGeometry(fill, pen, geometry);

        // Glyph centred in the upper part of the shield.
        var glyphText = new FormattedText(
            glyph, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface(FontFamily.Parse(Palette.FontFamily), FontStyle.Normal, FontWeight.Bold),
            shieldH * 0.34, Brushes.White);
        var glyphX = ox + (shieldW - glyphText.Width) / 2;
        var glyphY = oy + shieldH * 0.30 - glyphText.Height / 2;
        context.DrawText(glyphText, new Point(glyphX, glyphY));

        // Caption below the shield.
        if (!string.IsNullOrEmpty(_caption))
        {
            var captionText = new FormattedText(
                _caption, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
                new Typeface(FontFamily.Parse(Palette.FontFamily), FontStyle.Normal, FontWeight.SemiBold),
                17, new SolidColorBrush(color));
            var capX = (width - captionText.Width) / 2;
            var capY = height - captionH + (captionH - captionText.Height) / 2 - 2;
            context.DrawText(captionText, new Point(capX, capY));
        }
    }

    private static Geometry BuildShieldGeometry(double ox, double oy, double w, double h)
    {
        var left = ox;
        var right = ox + w;
        var top = oy;
        var midX = ox + w / 2;
        var bottom = oy + h;
        var r = w * 0.14;
        var shoulderY = top + h * 0.60;

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(new Point(left + r, top), isFilled: true);
            ctx.LineTo(new Point(right - r, top));
            ctx.CubicBezierTo(new Point(right, top), new Point(right, top), new Point(right, top + r)); // top-right
            ctx.LineTo(new Point(right, shoulderY));
            ctx.CubicBezierTo(
                new Point(right, bottom - h * 0.14),
                new Point(midX + w * 0.20, bottom - h * 0.03),
                new Point(midX, bottom));
            ctx.CubicBezierTo(
                new Point(midX - w * 0.20, bottom - h * 0.03),
                new Point(left, bottom - h * 0.14),
                new Point(left, shoulderY));
            ctx.LineTo(new Point(left, top + r));
            ctx.CubicBezierTo(new Point(left, top), new Point(left, top), new Point(left + r, top)); // top-left
            ctx.EndFigure(isClosed: true);
        }

        return geometry;
    }

    private static Color Lighten(Color c, double amount) => Color.FromArgb(
        c.A,
        (byte)Math.Min(255, c.R + 255 * amount),
        (byte)Math.Min(255, c.G + 255 * amount),
        (byte)Math.Min(255, c.B + 255 * amount));

    private static Color Darken(Color c, double amount) => Color.FromArgb(
        c.A,
        (byte)Math.Max(0, c.R - 255 * amount),
        (byte)Math.Max(0, c.G - 255 * amount),
        (byte)Math.Max(0, c.B - 255 * amount));
}
