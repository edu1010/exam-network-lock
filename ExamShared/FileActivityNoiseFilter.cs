namespace ExamShared;

/// <summary>Narrow exclusions for application startup data and generated editor metadata.</summary>
public static class FileActivityNoiseFilter
{
    public static IEnumerable<string> DocumentArguments(IEnumerable<string> arguments)
    {
        var tokens = arguments.ToArray();
        if (tokens.Length == 0) yield break;
        var process = ProcessPolicy.Normalize(tokens[0]);
        string[] options = process switch
        {
            "eclipse" => ["-startup", "--launcher.library", "-configuration", "-install", "-vm"],
            "java" or "javaw" => ["-cp", "-classpath", "--class-path", "--module-path", "-p"],
            "code" or "code-insiders" or "codium" => ["--user-data-dir", "--extensions-dir", "--logsPath", "--crash-reporter-directory"],
            "chrome" or "google-chrome" or "chromium" or "msedge" or "brave" => ["--user-data-dir", "--disk-cache-dir", "--log-file"],
            "firefox" => ["-profile", "--profile"],
            _ => []
        };
        var startupOptions = new HashSet<string>(options, StringComparer.Ordinal);
        var optionsEnded = false;
        for (var i = 1; i < tokens.Length; i++)
        {
            var token = tokens[i];
            if (!optionsEnded && token == "--") { optionsEnded = true; continue; }
            if (!optionsEnded && startupOptions.Contains(token.Split('=', 2)[0]))
            {
                if (!token.Contains('=') && i + 1 < tokens.Length && !tokens[i + 1].StartsWith('-')) i++;
                continue;
            }
            yield return token;
        }
    }

    // Only creation/rename notifications for these exact files are suppressed. A document opened
    // explicitly is still inspected, and explicitly blocked extensions take priority.
    public static bool IsEditorMetadata(string relativePath, bool windows)
    {
        var normalized = windows ? relativePath.Replace('\\', '/') : relativePath;
        var comparison = windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        string[] files = [".idea/workspace.xml", ".idea/tasks.xml", ".idea/misc.xml",
            ".idea/modules.xml", ".idea/vcs.xml", ".vscode/settings.json", ".vscode/extensions.json",
            ".vscode/launch.json", ".vscode/tasks.json"];
        return files.Any(file => string.Equals(normalized, file, comparison));
    }
}
