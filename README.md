# Exam Network Locking

Two WinForms apps for classroom exam locking, plus a log verifier.

Projects:
- `ExamConfigGenerator` (teacher) — builds a signed `exam.config`.
- `ExamLockClient` (student) — enforces the lockdown and shows the shield.
- `ExamShared` (shared models/services).
- `ExamLogVerifier` (console app to validate logs).

## Build

Prerequisite: install the .NET 8 SDK for Windows. The client targets
`net8.0-windows10.0.19041.0` to use the WinRT Radios API (Bluetooth toggle).

```powershell
dotnet build .\ExamLocking.sln
```

Open `ExamLocking.sln` in VS Code (C# Dev Kit) or Visual Studio.

## Configuration (teacher)

`ExamConfigGenerator` produces `exam.config`. Options:

- **Two passwords** (must be different):
  - **A — Restaurar Wi-Fi**: re-enables the radios. Does not close the app.
  - **B — Cerrar / Admin**: silences the shield, re-enables radios and **closes** the app.
    It is also the password that resolves a red AI alarm.
- **Radios**: disable Wi-Fi and/or Bluetooth on start (best-effort).
- **AI shield**: monitor active TCP connections against an editable blocklist of AI
  domains/IPs (defaults included: claude.ai, openai/chatgpt, gemini, copilot, perplexity…).
  Optionally raise the volume and beep on detection.
- **Allowed programs**: list of executables (e.g. `eclipse.exe`). Empty = no restriction.
- **Allowed file types**: comma-separated extensions (e.g. `.java,.txt,.pdf`). Empty = no
  restriction.
- **Work folder**: optionally restrict work to a folder and its subfolders. The base is
  **portable across machines/usernames** — choose where it resolves on the student PC:
  - *Where exam.config is* (recommended): the folder the student extracts the exam into.
  - *Student Desktop* / *Student Documents*: resolved per-user at runtime (e.g. it becomes
    `C:\Users\<student>\Desktop\<subfolder>` on each laptop).
  - *Fixed path*: an absolute path that must be identical on every machine (rarely advisable).
  An optional subfolder name is appended to the chosen base.

## Run

1. Start `ExamConfigGenerator`, fill the options and generate `exam.config`.
2. Copy `exam.config` to the student machine.
3. Start `ExamLockClient` (it auto-loads `exam.config` from its folder, or pick it).

### Student shield

A colored, minimizable shield:
- **Green** — everything OK.
- **Yellow** — an unknown program or file type was seen.
- **Red** — an AI connection, a forbidden file, or work outside the exam folder.

On a red AI detection the app beeps and raises the volume; the alarm persists until the
teacher enters **password B** (which also closes the app). The app cannot be closed without
password B; a force-close from Task Manager leaves the session marked unclean in the log.

### AI detection is a safety net

The AI shield monitors real TCP connections, so it fires **even if the Wi-Fi driver disable
failed on a particular laptop** — the "double check" the disable option can't guarantee.

### File/folder enforcement is a deterrent

File detection is heuristic: a `FileSystemWatcher` over the work folder plus command-line
inspection of document-opener apps (and teacher-allowed apps). It leaves evidence in the log;
it is not an exhaustive hook on every file open. Tune the allowed extensions / folder to
reduce false positives.

### Verify a log

```powershell
dotnet run --project .\ExamLogVerifier -- .\exam.config .\examlog.jsonl
```

## Files

All runtime files are stored next to the selected `exam.config`:
- `exam.config`
- `examlog.jsonl` (tamper-evident, hash-chained log)
- `session.lock` (unclean shutdown marker)

## Wi-Fi Adapter Name

The client uses `netsh` with the adapter name `Wi-Fi` by default. If your adapter uses a
different name (e.g., `Wi-Fi 2`), update `AdapterName` in
`ExamLockClient\NetworkAdapterService.cs`.

## Permissions

The client requires administrator rights (manifest `requireAdministrator`) to toggle the
network adapter and the Bluetooth radio.

## Notes

This is a practical deterrent system with tamper evidence, not a fully secure lock against an
admin user.
