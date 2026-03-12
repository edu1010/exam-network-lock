# Exam Network Locking

Two WinForms apps for classroom exam locking.

Projects:
- `ExamConfigGenerator`
- `ExamLockClient`
- `ExamShared` (shared models/services)

## Build

Prerequisite: install the .NET 8 SDK for Windows.

From the repo root:

```powershell
# restore/build
# (Use Developer PowerShell or standard PowerShell)
dotnet build .\ExamLocking.sln
```

Open `ExamLocking.sln` in VS Code (C# Dev Kit) or Visual Studio.

## Run

1. Start `ExamConfigGenerator`.
2. Enter unlock password and generate `exam.config`.
3. Copy `exam.config` to the student machine.
4. Start `ExamLockClient` and select `exam.config` if not auto-detected.

## Files

All runtime files are stored next to the selected `exam.config`:
- `exam.config`
- `examlog.jsonl` (tamper-evident log)
- `session.lock` (unclean shutdown marker)

## Wi-Fi Adapter Name

The client uses `netsh` with the adapter name `Wi-Fi` by default.
If your adapter uses a different name (e.g., `Wi-Fi 2`), update `AdapterName` in:
- `ExamLockClient\NetworkAdapterService.cs`

## Notes

This is a practical deterrent system with tamper evidence, not a fully secure lock against an admin user.
