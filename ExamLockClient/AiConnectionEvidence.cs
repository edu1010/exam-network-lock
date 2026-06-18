using System.Diagnostics;
using System.Management;
using System.Net;
using System.Text;

namespace ExamLockClient;

public sealed class AiConnectionEvidence
{
    public required string Destination { get; init; }
    public required IPAddress RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public string? CommandLine { get; init; }
    public bool IsStudentFacingProcess { get; init; }

    public string DedupKey =>
        $"{RemoteAddress}:{RemotePort}:{ProcessId?.ToString() ?? "unknown"}:{ProcessName ?? "unknown"}";

    public string Summary
    {
        get
        {
            var sb = new StringBuilder();
            sb.Append(Destination);
            if (RemotePort > 0)
            {
                sb.Append(':').Append(RemotePort);
            }

            if (ProcessId is null)
            {
                sb.Append(" | process unknown");
                return sb.ToString();
            }

            sb.Append(" | pid ").Append(ProcessId.Value);
            if (!string.IsNullOrWhiteSpace(ProcessName))
            {
                sb.Append(" | ").Append(ProcessName);
            }

            if (!string.IsNullOrWhiteSpace(ProcessPath))
            {
                sb.Append(" | ").Append(ProcessPath);
            }

            if (!string.IsNullOrWhiteSpace(CommandLine))
            {
                sb.Append(" | cmd: ").Append(Clip(CommandLine, 300));
            }

            return sb.ToString();
        }
    }

    private static string Clip(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";
}

internal sealed class ProcessEvidence
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public string? CommandLine { get; init; }

    public string Summary
    {
        get
        {
            var sb = new StringBuilder();
            sb.Append(ProcessName);
            if (!string.IsNullOrWhiteSpace(ProcessPath))
            {
                sb.Append(" | ").Append(ProcessPath);
            }

            if (!string.IsNullOrWhiteSpace(CommandLine))
            {
                sb.Append(" | cmd: ").Append(Clip(CommandLine, 300));
            }

            return sb.ToString();
        }
    }

    private static string Clip(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";
}

internal static class AiProcessClassifier
{
    private static readonly HashSet<string> StudentFacingProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Browsers.
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "browser.exe",
        "opera.exe", "opera_gx.exe", "vivaldi.exe", "arc.exe", "chromium.exe",
        "iexplore.exe", "safari.exe", "waterfox.exe", "librewolf.exe",

        // Editors and IDEs.
        "code.exe", "code-insiders.exe", "vscodium.exe", "codium.exe",
        "devenv.exe", "eclipse.exe", "netbeans.exe", "netbeans64.exe",
        "rider.exe", "rider64.exe", "idea.exe", "idea64.exe",
        "pycharm.exe", "pycharm64.exe", "webstorm.exe", "webstorm64.exe",
        "phpstorm.exe", "phpstorm64.exe", "clion.exe", "clion64.exe",
        "goland.exe", "goland64.exe", "rubymine.exe", "rubymine64.exe",
        "datagrip.exe", "datagrip64.exe", "dataspell.exe", "dataspell64.exe",
        "rustrover.exe", "rustrover64.exe", "studio64.exe", "androidstudio.exe",
        "sublime_text.exe", "notepad++.exe", "atom.exe", "zed.exe",
        "cursor.exe", "windsurf.exe",

        // CLI/dev runtimes commonly used by AI agents and API clients.
        "node.exe", "python.exe", "pythonw.exe", "dotnet.exe", "java.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe", "curl.exe", "wget.exe",

        // Dedicated AI tools.
        "codex.exe", "codex-cli.exe", "claude.exe", "claude-code.exe",
        "chatgpt.exe", "copilot.exe", "gemini.exe", "qwen.exe",
        "aider.exe", "goose.exe", "ollama.exe",
        "lmstudio.exe", "jan.exe", "gpt4all.exe", "msty.exe",
        "lobehub.exe", "anythingllm.exe"
    };

    private static readonly HashSet<string> DedicatedAiToolProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "codex.exe", "codex-cli.exe", "claude.exe", "claude-code.exe",
        "chatgpt.exe", "copilot.exe", "gemini.exe", "qwen.exe",
        "aider.exe", "goose.exe", "ollama.exe", "ollama app.exe",
        "lmstudio.exe", "jan.exe", "gpt4all.exe", "msty.exe",
        "lobehub.exe", "anythingllm.exe", "cursor.exe", "windsurf.exe",
        "tabnine.exe", "codeium.exe"
    };

    private static readonly string[] AiToolCommandMarkers =
    {
        "@openai/codex",
        "openai-codex",
        "codex-cli",
        " codex ",
        "\\codex",
        "/codex",
        "@anthropic-ai/claude-code",
        "@anthropic-ai\\claude-code",
        "claude-code",
        " claude ",
        "\\claude",
        "/claude",
        "@google/gemini-cli",
        "gemini-cli",
        " qwen ",
        "qwen-code",
        " aider ",
        "\\aider",
        "/aider",
        " goose ",
        "\\goose",
        "/goose",
        "cursor-agent",
        "continue-agent",
        "githubcopilot",
        "copilot-chat"
    };

    public static ProcessEvidence? TryGetProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var name = SafeProcessName(process);
            if (string.IsNullOrWhiteSpace(name))
            {
                return new ProcessEvidence { ProcessId = processId, ProcessName = "unknown.exe" };
            }

            return new ProcessEvidence
            {
                ProcessId = processId,
                ProcessName = name,
                ProcessPath = SafeProcessPath(process),
                CommandLine = SafeCommandLine(processId)
            };
        }
        catch
        {
            return null;
        }
    }

    public static bool IsStudentFacing(ProcessEvidence? evidence)
    {
        if (evidence is null)
        {
            return false;
        }

        return StudentFacingProcesses.Contains(evidence.ProcessName) ||
               IsAiToolCommandLine(evidence.CommandLine);
    }

    public static bool IsDedicatedAiTool(ProcessEvidence? evidence)
    {
        if (evidence is null)
        {
            return false;
        }

        return DedicatedAiToolProcesses.Contains(evidence.ProcessName) ||
               IsAiToolCommandLine(evidence.CommandLine);
    }

    public static bool IsDedicatedAiToolProcessName(string? processName) =>
        !string.IsNullOrWhiteSpace(processName) && DedicatedAiToolProcesses.Contains(processName);

    private static string SafeProcessName(Process process)
    {
        try
        {
            var name = process.ProcessName;
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? name
                : name + ".exe";
        }
        catch
        {
            return "unknown.exe";
        }
    }

    private static string? SafeProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static string? SafeCommandLine(int processId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + processId);
            using var results = searcher.Get();
            foreach (var obj in results)
            {
                return obj["CommandLine"] as string;
            }
        }
        catch
        {
        }

        return null;
    }

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
