using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace ExamDesktop.Ui;

/// <summary>EN / CA / ES switcher. Language indices match each app's Language enum (En=0, Ca=1, Es=2).</summary>
public sealed class LanguageBar : StackPanel
{
    private static readonly (string Code, string Name)[] Languages = { ("EN", "English"), ("CA", "Català"), ("ES", "Español") };
    private readonly List<Button> _buttons = new();

    public LanguageBar(Action<int> onSelect)
    {
        Orientation = Orientation.Horizontal;
        HorizontalAlignment = HorizontalAlignment.Right;
        VerticalAlignment = VerticalAlignment.Center;
        Spacing = 6;

        for (var i = 0; i < Languages.Length; i++)
        {
            var index = i;
            var button = new Button
            {
                Content = Languages[i].Code,
                MinWidth = 44,
                HorizontalContentAlignment = HorizontalAlignment.Center,
                Background = Palette.Surface,
                BorderThickness = new Thickness(1)
            };
            ToolTip.SetTip(button, Languages[i].Name);
            button.Click += (_, _) => onSelect(index);
            _buttons.Add(button);
            Children.Add(button);
        }
    }

    /// <summary>Highlights the active language.</summary>
    public void Select(int index)
    {
        for (var i = 0; i < _buttons.Count; i++)
        {
            var selected = i == index;
            _buttons[i].BorderBrush = selected ? Palette.Accent : Palette.Border;
            _buttons[i].BorderThickness = new Thickness(selected ? 2 : 1);
            _buttons[i].FontWeight = selected ? FontWeight.Bold : FontWeight.Normal;
        }
    }
}
