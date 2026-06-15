using System.Drawing.Drawing2D;

namespace ExamConfigGenerator;

/// <summary>Small flag bitmaps drawn with GDI+ (no external image files).</summary>
internal static class Flags
{
    public static Bitmap For(Language language) => language switch
    {
        Language.En => Uk(),
        Language.Ca => Catalonia(),
        _ => Spain()
    };

    private const int W = 26;
    private const int H = 18;

    private static Bitmap NewFlag(out Graphics g)
    {
        var bmp = new Bitmap(W, H);
        g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        return bmp;
    }

    public static Bitmap Spain()
    {
        var bmp = NewFlag(out var g);
        using (g)
        {
            using var rb = new SolidBrush(Color.FromArgb(198, 11, 30));
            using var yb = new SolidBrush(Color.FromArgb(255, 196, 0));
            g.FillRectangle(rb, 0, 0, W, H);
            g.FillRectangle(yb, 0, H * 0.25f, W, H * 0.5f);
        }

        return bmp;
    }

    public static Bitmap Catalonia()
    {
        var bmp = NewFlag(out var g);
        using (g)
        {
            using var yb = new SolidBrush(Color.FromArgb(255, 209, 0));
            using var rb = new SolidBrush(Color.FromArgb(218, 18, 26));
            g.FillRectangle(yb, 0, 0, W, H);
            float stripe = H / 9f;
            for (var i = 1; i < 9; i += 2)
            {
                g.FillRectangle(rb, 0, i * stripe, W, stripe);
            }
        }

        return bmp;
    }

    public static Bitmap Uk()
    {
        var bmp = NewFlag(out var g);
        using (g)
        {
            var red = Color.FromArgb(200, 16, 46);
            using var bg = new SolidBrush(Color.FromArgb(1, 33, 105));
            g.FillRectangle(bg, 0, 0, W, H);
            g.SetClip(new Rectangle(0, 0, W, H));

            using (var whiteDiag = new Pen(Color.White, H * 0.34f))
            using (var redDiag = new Pen(red, H * 0.16f))
            {
                g.DrawLine(whiteDiag, 0, 0, W, H);
                g.DrawLine(whiteDiag, 0, H, W, 0);
                g.DrawLine(redDiag, 0, 0, W, H);
                g.DrawLine(redDiag, 0, H, W, 0);
            }

            using (var white = new SolidBrush(Color.White))
            {
                g.FillRectangle(white, W / 2f - H * 0.20f, 0, H * 0.40f, H);
                g.FillRectangle(white, 0, H / 2f - H * 0.20f, W, H * 0.40f);
            }

            using (var rc = new SolidBrush(red))
            {
                g.FillRectangle(rc, W / 2f - H * 0.11f, 0, H * 0.22f, H);
                g.FillRectangle(rc, 0, H / 2f - H * 0.11f, W, H * 0.22f);
            }
        }

        return bmp;
    }
}
