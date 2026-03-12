using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ExamShared;

namespace ExamLogVerifier;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: ExamLogVerifier <exam.config> <examlog.jsonl>");
            return 2;
        }

        var configPath = args[0];
        var logPath = args[1];

        if (!File.Exists(configPath))
        {
            Console.WriteLine($"Config not found: {configPath}");
            return 2;
        }

        if (!File.Exists(logPath))
        {
            Console.WriteLine($"Log not found: {logPath}");
            return 2;
        }

        try
        {
            var configJson = File.ReadAllText(configPath, Encoding.UTF8);
            var envelope = ConfigSerializer.DeserializeEnvelope(configJson);
            var payloadJson = ConfigSerializer.SerializePayload(envelope.Payload);

            if (!ConfigIntegrityService.VerifyHmac(payloadJson, envelope.HmacBase64))
            {
                Console.WriteLine("Config HMAC is invalid.");
                return 1;
            }

            var logKey = Convert.FromBase64String(envelope.Payload.LogSecretBase64);

            var ok = VerifyLog(logPath, logKey);
            Console.WriteLine(ok ? "Log integrity: OK" : "Log integrity: FAIL");
            return ok ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Verification failed: {ex.Message}");
            return 1;
        }
    }

    private static bool VerifyLog(string logPath, byte[] key)
    {
        var ok = true;
        var prevHmac = "GENESIS";
        var lineNumber = 0;

        foreach (var line in File.ReadLines(logPath, Encoding.UTF8))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            lineNumber++;
            try
            {
                var entry = JsonSerializer.Deserialize<LogEntry>(line);
                if (entry is null)
                {
                    Console.WriteLine($"FAIL line {lineNumber} (invalid JSON)");
                    ok = false;
                    continue;
                }

                var data = entry.EventData ?? string.Empty;
                var payload = $"{entry.Sequence}|{entry.Timestamp}|{entry.EventType}|{data}|{prevHmac}";
                var calc = ComputeHmacBase64(key, payload);

                var prevMatches = entry.PrevHmacBase64 == prevHmac;
                var hmacMatches = FixedEqualsBase64(calc, entry.HmacBase64);

                if (!prevMatches || !hmacMatches)
                {
                    Console.WriteLine($"FAIL line {lineNumber} (seq {entry.Sequence})");
                    ok = false;
                }
                else
                {
                    Console.WriteLine($"OK line {lineNumber} (seq {entry.Sequence})");
                }

                prevHmac = entry.HmacBase64;
            }
            catch
            {
                Console.WriteLine($"FAIL line {lineNumber} (invalid JSON)");
                ok = false;
            }
        }

        return ok;
    }

    private static string ComputeHmacBase64(byte[] key, string text)
    {
        using var hmac = new HMACSHA256(key);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        return Convert.ToBase64String(mac);
    }

    private static bool FixedEqualsBase64(string a, string b)
    {
        var ba = Convert.FromBase64String(a);
        var bb = Convert.FromBase64String(b);
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
