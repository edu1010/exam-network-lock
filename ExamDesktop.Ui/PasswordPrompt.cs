using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace ExamDesktop.Ui;

/// <summary>Modal password prompt. Returns the typed password, or null when canceled.</summary>
public static class PasswordPrompt
{
    public static async Task<string?> Show(Window owner, string text, string title, string okText, string cancelText)
    {
        string? result = null;
        var box = new TextBox { PasswordChar = '•', MinWidth = 300 };
        var ok = Ui.Primary(new Button { Content = okText, MinWidth = 90, HorizontalContentAlignment = HorizontalAlignment.Center, IsDefault = true });
        var cancel = Ui.Secondary(new Button { Content = cancelText, MinWidth = 90, HorizontalContentAlignment = HorizontalAlignment.Center, IsCancel = true });

        var dialog = new Window
        {
            Title = title,
            SizeToContent = SizeToContent.WidthAndHeight,
            MinWidth = 380,
            MaxWidth = 560,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = Palette.Background,
            Content = new Border
            {
                BorderBrush = Palette.Accent,
                BorderThickness = new Thickness(4, 0, 0, 0),
                Padding = new Thickness(18, 16),
                Child = new StackPanel
                {
                    Spacing = 12,
                    Children =
                    {
                        new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = Palette.Text },
                        box,
                        new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Children = { cancel, ok } }
                    }
                }
            }
        };

        ok.Click += (_, _) =>
        {
            result = box.Text ?? string.Empty;
            dialog.Close();
        };
        cancel.Click += (_, _) => dialog.Close();
        dialog.Opened += (_, _) => box.Focus();

        await dialog.ShowDialog(owner);
        return result;
    }
}
