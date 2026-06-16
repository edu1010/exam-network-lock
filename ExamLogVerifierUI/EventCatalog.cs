using ExamShared;

namespace ExamLogVerifierUI;

internal enum Severity
{
    Critical, // clear misconduct / AI / forbidden file — drives a RED log status
    Warning,  // suspicious but softer — drives an AMBER log status
    Good,     // expected, benign confirmations
    Info      // neutral lifecycle / radio events
}

/// <summary>
/// Classifies log event types by severity, supplies their pastel row colors, and resolves a
/// localized display label. Severity here is a presentation concern (the integrity check lives in
/// <see cref="LogVerifier"/>); it decides the colored status of each log and each event row.
/// </summary>
internal static class EventCatalog
{
    public const string InvalidJson = "INVALID_JSON";

    private static readonly Dictionary<string, Severity> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        // Critical — a student contacted AI, opened a forbidden file, left the folder, or ran a VM.
        [LogEvents.AiDetected] = Severity.Critical,
        [LogEvents.AiDnsDetected] = Severity.Critical,
        [LogEvents.AiToolDetected] = Severity.Critical,
        [LogEvents.VmDetected] = Severity.Critical,
        [LogEvents.ForbiddenFile] = Severity.Critical,
        [LogEvents.OutsideFolder] = Severity.Critical,
        // The shield's top alarm state — only raised alongside a real incident on the client.
        [LogEvents.ShieldRed] = Severity.Critical,

        // Warning — worth a look: unknown app/file, a dirty previous session, failed admin attempts.
        [LogEvents.UnknownProcess] = Severity.Warning,
        [LogEvents.UnknownFile] = Severity.Warning,
        [LogEvents.UncleanPreviousSession] = Severity.Warning,
        [LogEvents.AdminAuthFailed] = Severity.Warning,
        [LogEvents.UnlockFailed] = Severity.Warning,
        [LogEvents.ShieldYellow] = Severity.Warning,
        [LogEvents.WifiDisableFailed] = Severity.Warning,
        [LogEvents.WifiEnableFailed] = Severity.Warning,
        [LogEvents.BluetoothFailed] = Severity.Warning,

        // Good — benign confirmations.
        [LogEvents.AppStarted] = Severity.Good,
        [LogEvents.ConfigValid] = Severity.Good,
        [LogEvents.UnlockSuccess] = Severity.Good,
        [LogEvents.AiCleared] = Severity.Good,
        [LogEvents.ShieldGreen] = Severity.Good,
        [LogEvents.WifiRestored] = Severity.Good,
        [LogEvents.NormalExit] = Severity.Good,

        // Info — neutral lifecycle / radio toggles.
        [LogEvents.WifiDisabled] = Severity.Info,
        [LogEvents.WifiEnabled] = Severity.Info,
        [LogEvents.BluetoothDisabled] = Severity.Info,
        [LogEvents.BluetoothEnabled] = Severity.Info,
        [LogEvents.AdminClose] = Severity.Info,
    };

    public static Severity SeverityOf(string? eventType)
    {
        if (string.IsNullOrEmpty(eventType))
        {
            return Severity.Info;
        }

        if (eventType == InvalidJson)
        {
            return Severity.Critical;
        }

        return Map.TryGetValue(eventType, out var s) ? s : Severity.Warning; // unknown type → be cautious
    }

    public static bool IsCritical(string? eventType) => SeverityOf(eventType) == Severity.Critical;

    public static bool IsIncident(string? eventType)
    {
        var s = SeverityOf(eventType);
        return s is Severity.Critical or Severity.Warning;
    }

    /// <summary>Localized, human-readable name for a raw event type, falling back to the raw token.</summary>
    public static string Label(string? eventType)
    {
        if (string.IsNullOrEmpty(eventType))
        {
            return "";
        }

        var localized = Lang.T("ev." + eventType);
        return localized == "ev." + eventType ? eventType : localized;
    }

    public static Color RowBg(Severity s) => s switch
    {
        Severity.Critical => Theme.RedBg,
        Severity.Warning => Theme.AmberBg,
        Severity.Good => Theme.GreenBg,
        _ => Theme.Surface
    };

    public static Color RowText(Severity s) => s switch
    {
        Severity.Critical => Theme.RedText,
        Severity.Warning => Theme.AmberText,
        Severity.Good => Theme.GreenText,
        _ => Theme.TextMuted
    };
}
