using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace ExamDesktop.Ui;

public enum MessageKind { Info, Warning, Error }

/// <summary>Minimal modal message box (Avalonia ships none).</summary>
public static class MessageBox
{
    public static Task Show(Window owner, string text, string title, MessageKind kind = MessageKind.Info)
    {
        var accent = kind switch
        {
            MessageKind.Error => Palette.RedText,
            MessageKind.Warning => Palette.AmberText,
            _ => Palette.Accent
        };

        var ok = Ui.Primary(new Button
        {
            Content = "OK",
            MinWidth = 90,
            HorizontalAlignment = HorizontalAlignment.Right,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            IsDefault = true,
            IsCancel = true
        });

        var dialog = new Window
        {
            Title = title,
            SizeToContent = SizeToContent.WidthAndHeight,
            MinWidth = 340,
            MaxWidth = 560,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = Palette.Background,
            Content = new Border
            {
                BorderBrush = accent,
                BorderThickness = new Thickness(4, 0, 0, 0),
                Padding = new Thickness(18, 16),
                Child = new StackPanel
                {
                    Spacing = 16,
                    Children =
                    {
                        new SelectableTextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = Palette.Text },
                        ok
                    }
                }
            }
        };

        ok.Click += (_, _) => dialog.Close();
        return dialog.ShowDialog(owner);
    }
}
