using ExamShared;

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
    Console.WriteLine("PASS: " + message);
}

var policy = new ProcessPolicy(["code.exe", "firefox"], ["firefox.exe"], ["svchost.exe", "systemd"]);
Check(policy.Evaluate("/usr/bin/firefox", true) == ProcessDecision.Blocked, "Prohibited program detected in startup baseline");
Check(policy.Evaluate("FIREFOX.EXE", false) == ProcessDecision.Blocked, "Prohibited overrides allowed on Windows");
Check(policy.Evaluate("code", false) == ProcessDecision.Allowed, "Executable suffix normalized across platforms");
Check(policy.Evaluate("svchost.exe", false) == ProcessDecision.Allowed, "Known Windows system process exempt");
Check(policy.Evaluate("systemd", false) == ProcessDecision.Allowed, "Known Linux system process exempt");
Check(policy.Evaluate("helper", true) == ProcessDecision.Allowed, "Existing auxiliary process exempt");
Check(policy.Evaluate("helper", false) == ProcessDecision.Unknown, "New unlisted helper is a warning, not a prohibition");
Check(policy.Evaluate(null, false) == ProcessDecision.Allowed, "Unreadable process name does not fabricate an incident");
var blockedOnly = new ProcessPolicy([], ["firefox"], []);
Check(blockedOnly.Evaluate("helper", false) == ProcessDecision.Allowed, "Blocked-only mode does not flag unrelated helpers");
Check(blockedOnly.Evaluate("firefox.exe", false) == ProcessDecision.Blocked, "Blocked-only mode reports configured applications");
Check(new ProcessPolicy([], ["systemd"], ["systemd"]).Evaluate("systemd", true) == ProcessDecision.Blocked,
    "Explicit prohibition overrides a system-name exemption without terminating anything");
Check(ProcessPolicy.Normalize("/usr/bin/python3.11") == "python3.11", "Versioned executable names preserved");

var legacy = new ConfigPayload();
var legacyJson = ConfigSerializer.SerializePayload(legacy);
Check(!legacyJson.Contains("blockedProcesses"), "Absent prohibited list preserves legacy serialized fields");
var envelope = new ConfigEnvelope { Payload = legacy, HmacBase64 = ConfigIntegrityService.ComputeHmacBase64(legacyJson) };
var loaded = ConfigSerializer.DeserializeEnvelope(ConfigSerializer.SerializeEnvelope(envelope));
Check(loaded.Payload.BlockedProcesses is null && ConfigIntegrityService.VerifyHmac(
    ConfigSerializer.SerializePayload(loaded.Payload), loaded.HmacBase64), "Legacy configuration HMAC round trip");
var configured = new ConfigPayload { BlockedProcesses = ["firefox.exe"] };
var json = ConfigSerializer.SerializePayload(configured);
var signed = ConfigSerializer.SerializeEnvelope(new ConfigEnvelope
    { Payload = configured, HmacBase64 = ConfigIntegrityService.ComputeHmacBase64(json) });
var roundTrip = ConfigSerializer.DeserializeEnvelope(signed);
Check(roundTrip.Payload.BlockedProcesses?.Single() == "firefox.exe" && ConfigIntegrityService.VerifyHmac(
    ConfigSerializer.SerializePayload(roundTrip.Payload), roundTrip.HmacBase64), "Prohibited list is serialized and signed");
var tampered = ConfigSerializer.DeserializeEnvelope(signed.Replace("firefox.exe", "allowed.exe"));
Check(!ConfigIntegrityService.VerifyHmac(ConfigSerializer.SerializePayload(tampered.Payload), tampered.HmacBase64),
    "Tampering with prohibited programs invalidates the signature");
