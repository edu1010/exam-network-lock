using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;

namespace ExamDesktop.Ui;

/// <summary>Small layout helpers so the code-only windows read like the WinForms originals.</summary>
public static class Ui
{
    public static T Cell<T>(T control, int row, int col = 0, int colSpan = 1) where T : Control
    {
        Grid.SetRow(control, row);
        Grid.SetColumn(control, col);
        if (colSpan > 1)
        {
            Grid.SetColumnSpan(control, colSpan);
        }

        return control;
    }

    /// <summary>Removes the item padding so templated rows sit edge to edge like a data grid.</summary>
    public static ListBox TableRows(ListBox list)
    {
        list.Styles.Add(new Style(x => x.OfType<ListBoxItem>())
        {
            Setters =
            {
                new Setter(TemplatedControl.PaddingProperty, new Thickness(0)),
                new Setter(Layoutable.MarginProperty, new Thickness(0, 0, 0, 1))
            }
        });
        // Rows paint their own state colour, so mark the selection with an accent bar instead.
        list.Styles.Add(new Style(x => x.OfType<ListBoxItem>().Class(":selected"))
        {
            Setters =
            {
                new Setter(TemplatedControl.BorderBrushProperty, Palette.Accent),
                new Setter(TemplatedControl.BorderThicknessProperty, new Thickness(4, 0, 0, 0))
            }
        });
        return list;
    }

    public static Border Card(Control child, Thickness? margin = null) => new()
    {
        Background = Palette.Surface,
        BorderBrush = Palette.Border,
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(6),
        Padding = new Thickness(12),
        Margin = margin ?? new Thickness(0, 0, 0, 10),
        Child = child
    };

    public static TextBlock Muted(string text = "") => new()
    {
        Text = text,
        Foreground = Palette.TextMuted,
        TextWrapping = TextWrapping.Wrap
    };

    public static Button Primary(Button button)
    {
        button.Background = Palette.Accent;
        button.Foreground = Brushes.White;
        button.FontWeight = FontWeight.SemiBold;
        return button;
    }

    public static Button Secondary(Button button)
    {
        button.Background = Palette.Surface;
        button.BorderBrush = Palette.Border;
        button.BorderThickness = new Thickness(1);
        button.Padding = new Thickness(10, 5);
        return button;
    }

    /// <summary>Text input stretched to fill, followed by auto-sized buttons (like InputWithButtons in WinForms).</summary>
    public static Grid InputWithButtons(Control input, params Button[] buttons)
    {
        var grid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        grid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Star));
        grid.Children.Add(Cell(input, 0, 0));
        for (var i = 0; i < buttons.Length; i++)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
            buttons[i].Margin = new Thickness(6, 0, 0, 0);
            buttons[i].VerticalAlignment = VerticalAlignment.Stretch;
            buttons[i].VerticalContentAlignment = VerticalAlignment.Center;
            grid.Children.Add(Cell(buttons[i], 0, i + 1));
        }

        return grid;
    }
}
