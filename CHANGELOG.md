# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-01-06

### Added

- Platform-neutral core library (`EvtLogTriage.Core`) with a normalized `EventRecord` model.
- Nine correlation rules: brute force, password spray, off-hours logon, privilege escalation,
  account create-escalate-delete lifecycle, audit log tampering, suspicious service installation,
  explicit-credential logon bursts, and a source-address-based impossible-travel heuristic.
- JSON reader (PowerShell `Get-WinEvent | ConvertTo-Json` shape and a simplified flat schema) and
  CSV reader (`Export-Csv` shape), both platform-neutral.
- Windows-only EVTX/live-channel reader (`EvtLogTriage.Windows`), guarded with
  `[SupportedOSPlatform("windows")]`.
- CLI (`evtlog-triage`) with table, JSON, and timeline output; `--since`, `--severity`,
  `--fail-on`, `--rules`/`--exclude`, `--expected-admins`, and `--business-hours-*` options.
- 90 xUnit tests covering every rule firing and not firing, including window-boundary behavior.
- Synthetic sample logs (JSON and CSV) with RFC 5737 documentation IP ranges.
