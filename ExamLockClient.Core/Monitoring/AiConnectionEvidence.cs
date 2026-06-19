using System.Net;
using System.Text;

namespace ExamLockClient.Core.Monitoring;

/// <summary>Everything known about a flagged AI connection: the endpoint plus the owning process.</summary>
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
