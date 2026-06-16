using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ExamShared;

/// <summary>
/// Overall integrity verdict for a log file. <see cref="Empty"/> means the file parsed but held no
/// entries; <see cref="Tampered"/> means at least one line failed the HMAC chain (edited/removed/added).
/// </summary>
public enum LogIntegrity
{
    Ok,
    Tampered,
    Empty
}

/// <summary>A single parsed log line plus whether its place in the HMAC chain is intact.</summary>
public sealed class VerifiedLogEntry
{
    public LogEntry Entry { get; init; } = new();
    public int LineNumber { get; init; }

    /// <summary>True when both the recomputed HMAC and the recorded previous-HMAC link match.</summary>
    public bool Valid { get; init; }

    /// <summary>True when the JSON line itself could not be parsed (corrupt / hand-edited).</summary>
    public bool Unparsed { get; init; }
}

public sealed class LogVerificationResult
{
    public bool ReadOk { get; init; }
    public string? Error { get; init; }
    public LogIntegrity Integrity { get; init; }

    /// <summary>1-based line number of the first chain break, or -1 if the chain is intact.</summary>
    public int FirstBrokenLine { get; init; } = -1;

    public IReadOnlyList<VerifiedLogEntry> Entries { get; init; } = Array.Empty<VerifiedLogEntry>();
}

/// <summary>
/// Recomputes the HMAC chain of a <c>examlog.jsonl</c> file written by <see cref="SecureLogService"/>
/// and reports, per line, whether it is intact. This is the canonical, UI-agnostic verifier: the
/// terminal <c>ExamLogVerifier</c> keeps its own inline copy, while richer tools (the GUI) build on
/// this so every consumer applies the exact same chain rule the client used to write the log.
/// </summary>
public static class LogVerifier
{
    public static LogVerificationResult Verify(string logPath, byte[] logKey)
    {
        IEnumerable<string> lines;
        try
        {
            // Read fully first so a mid-stream IO error surfaces as a clean failure, not a partial chain.
            lines = File.ReadAllLines(logPath, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            return new LogVerificationResult { ReadOk = false, Error = ex.Message };
        }

        var entries = new List<VerifiedLogEntry>();
        var prevHmac = "GENESIS";
        var lineNumber = 0;
        var firstBroken = -1;
        var anyInvalid = false;

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            lineNumber++;

            LogEntry? entry = null;
            try
            {
                entry = JsonSerializer.Deserialize<LogEntry>(line);
            }
            catch
            {
                entry = null;
            }

            if (entry is null)
            {
                anyInvalid = true;
                if (firstBroken < 0)
                {
                    firstBroken = lineNumber;
                }

                entries.Add(new VerifiedLogEntry
                {
                    Entry = new LogEntry { Sequence = -1, EventType = "INVALID_JSON", Timestamp = "" },
                    LineNumber = lineNumber,
                    Valid = false,
                    Unparsed = true
                });

                // A corrupt line breaks the chain; keep prevHmac so the following lines also flag mismatch.
                continue;
            }

            var data = entry.EventData ?? string.Empty;
            var payload = $"{entry.Sequence}|{entry.Timestamp}|{entry.EventType}|{data}|{prevHmac}";
            var calc = ComputeHmac(logKey, payload);

            var prevMatches = entry.PrevHmacBase64 == prevHmac;
            var hmacMatches = FixedEqualsBase64(calc, entry.HmacBase64);
            var valid = prevMatches && hmacMatches;

            if (!valid)
            {
                anyInvalid = true;
                if (firstBroken < 0)
                {
                    firstBroken = lineNumber;
                }
            }

            entries.Add(new VerifiedLogEntry { Entry = entry, LineNumber = lineNumber, Valid = valid });
            prevHmac = entry.HmacBase64;
        }

        var integrity = entries.Count == 0
            ? LogIntegrity.Empty
            : anyInvalid ? LogIntegrity.Tampered : LogIntegrity.Ok;

        return new LogVerificationResult
        {
            ReadOk = true,
            Integrity = integrity,
            FirstBrokenLine = firstBroken,
            Entries = entries
        };
    }

    private static string ComputeHmac(byte[] key, string text)
    {
        using var hmac = new HMACSHA256(key);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        return Convert.ToBase64String(mac);
    }

    private static bool FixedEqualsBase64(string a, string b)
    {
        try
        {
            var ba = Convert.FromBase64String(a);
            var bb = Convert.FromBase64String(b);
            return CryptographicOperations.FixedTimeEquals(ba, bb);
        }
        catch
        {
            // A non-base64 recorded HMAC means the line was hand-edited: treat as a mismatch.
            return false;
        }
    }
}
