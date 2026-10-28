using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace ExamDesktop.Ui;

/// <summary>Thin wrappers over Avalonia's StorageProvider returning local paths (or null when canceled).</summary>
public static class Pickers
{
    public static async Task<string[]> OpenFiles(Window owner, string title, bool multiple, params (string Name, string[] Patterns)[] filters)
    {
        var files = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = multiple,
            FileTypeFilter = BuildFilters(filters)
        });

        return files.Select(f => f.TryGetLocalPath()).OfType<string>().ToArray();
    }

    public static async Task<string?> OpenFile(Window owner, string title, params (string Name, string[] Patterns)[] filters) =>
        (await OpenFiles(owner, title, false, filters)).FirstOrDefault();

    public static async Task<string?> SaveFile(Window owner, string title, string suggestedName, string extension, params (string Name, string[] Patterns)[] filters)
    {
        var file = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = extension,
            ShowOverwritePrompt = true,
            FileTypeChoices = BuildFilters(filters)
        });

        return file?.TryGetLocalPath();
    }

    public static async Task<string?> OpenFolder(Window owner, string title)
    {
        var folders = await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false
        });

        return folders.Select(f => f.TryGetLocalPath()).OfType<string>().FirstOrDefault();
    }

    private static List<FilePickerFileType> BuildFilters((string Name, string[] Patterns)[] filters)
    {
        var list = filters.Select(f => new FilePickerFileType(f.Name) { Patterns = f.Patterns }).ToList();
        list.Add(FilePickerFileTypes.All);
        return list;
    }
}
