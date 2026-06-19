using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>
/// Classifies a process as a student-facing app (browser/IDE/dev tool), a dedicated AI tool, or a
/// virtual machine. All names are bare/lower-cased (see <see cref="ProcessNames"/>) so the same
/// table matches "chrome.exe" on Windows and "chrome" on Linux.
/// </summary>
public static class AiProcessClassifier
{
    private static readonly HashSet<string> StudentFacing = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browsers.
        "chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
        "msedge", "microsoft-edge", "microsoft-edge-stable", "firefox", "firefox-bin", "firefox-esr",
        "brave", "brave-browser", "browser", "opera", "opera_gx", "vivaldi", "vivaldi-bin", "arc",
        "iexplore", "safari", "waterfox", "librewolf", "epiphany", "falkon", "qutebrowser", "midori",

        // Editors and IDEs.
        "code", "code-insiders", "codium", "vscodium", "devenv", "eclipse", "netbeans",
        "rider", "idea", "pycharm", "webstorm", "phpstorm", "clion", "goland", "rubymine",
        "datagrip", "dataspell", "rustrover", "studio", "androidstudio", "sublime_text", "sublime-text",
        "notepad++", "atom", "zed", "cursor", "windsurf", "gedit", "kate", "kwrite",
        "gnome-text-editor", "nano", "vim", "nvim", "emacs", "geany", "bluefish",

        // CLI/dev runtimes commonly used by AI agents and API clients.
        "node", "nodejs", "python", "python3", "pythonw", "dotnet", "java",
        "powershell", "pwsh", "cmd", "bash", "sh", "zsh", "fish", "curl", "wget", "deno", "bun",

        // Dedicated AI tools.
        "codex", "codex-cli", "claude", "claude-code", "chatgpt", "copilot", "gemini", "qwen",
        "aider", "goose", "ollama", "lmstudio", "jan", "gpt4all", "msty", "lobehub", "anythingllm"
    };

    private static readonly HashSet<string> DedicatedAiTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "codex", "codex-cli", "claude", "claude-code", "chatgpt", "copilot", "gemini", "qwen",
        "aider", "goose", "ollama", "ollama app", "lmstudio", "jan", "gpt4all", "msty",
        "lobehub", "anythingllm", "cursor", "windsurf", "tabnine", "codeium"
    };

    private static readonly string[] AiToolCommandMarkers =
    {
        "@openai/codex", "openai-codex", "codex-cli", " codex ", "\\codex", "/codex",
        "@anthropic-ai/claude-code", "@anthropic-ai\\claude-code", "claude-code", " claude ", "\\claude", "/claude",
        "@google/gemini-cli", "gemini-cli", " qwen ", "qwen-code",
        " aider ", "\\aider", "/aider", " goose ", "\\goose", "/goose",
        "cursor-agent", "continue-agent", "githubcopilot", "copilot-chat"
    };

    public static bool IsStudentFacing(ProcessInfo? process)
    {
        if (process is null)
        {
            return false;
        }

        return StudentFacing.Contains(process.Name) || IsAiToolCommandLine(process.CommandLine);
    }

    public static bool IsDedicatedAiTool(ProcessInfo? process)
    {
        if (process is null)
        {
            return false;
        }

        return DedicatedAiTools.Contains(process.Name) || IsAiToolCommandLine(process.CommandLine);
    }

    public static bool IsDedicatedAiToolName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && DedicatedAiTools.Contains(name);

    private static bool IsAiToolCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        var normalized = " " + commandLine
            .Replace('"', ' ')
            .Replace('\'', ' ')
            .ToLowerInvariant() + " ";

        return AiToolCommandMarkers.Any(normalized.Contains);
    }
}
