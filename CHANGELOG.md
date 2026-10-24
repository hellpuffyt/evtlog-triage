# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Malformed or empty JSON, a non-object array element, a truncated `/Date(` timestamp, an unknown
  option and invalid option values (`--business-hours-start 25:99`, `--severity Loud`) crashed the
  CLI with an unhandled exception; they now print an error and exit with code 2.
- `--severity 42` / `--fail-on 7` were accepted as undefined severities; `--business-hours-start 9`
  was read as nine *days*; a business-hours end before the start silently marked every logon as
  off-hours. All are now rejected with a clear message.
- `--since` without an offset was read in the machine's local time zone (and culture) while event
  timestamps without an offset are read as UTC; it is now UTC and culture-invariant.
- A second positional argument was silently ignored; it is now a usage error.
- A brute-force or explicit-credential burst longer than the threshold was split into several
  findings that each reported only `threshold` events (40 failures became four "10 failed logons"
  findings); a burst now covers every event within the window of its first event.
- Account and source address values of `-` (Windows' "no value", e.g. `IpAddress` on local
  logons) or blank were treated as a real key, merging unrelated events into one brute-force group.
- Object-valued account fields (e.g. `UserId` from `Get-WinEvent | ConvertTo-Json`) were used as
  the account name as raw JSON text.
- The Windows `.evtx`/live reader took the account and address from fixed positions 5 and 18 for
  every event ID, which is wrong for 4625 (position 18 is `ProcessName`), 4672, 4732, 1102, and
  hid 7045's `ImagePath` from the service-install rule. Records are now mapped from their XML by
  field name through the new platform-neutral `EventXmlParser`.
- The `#TYPE` line written by Windows PowerShell 5.1's `Export-Csv` is skipped.

### Changed

- README: the CLI reads JSON/CSV only (EVTX/live channels are a Windows library API), raw
  `Get-WinEvent | ConvertTo-Json` output lacks the fields most rules need, and time-zone handling is
  documented.

### Added

- `EventXmlParser` with tests on synthetic event XML; regression tests for every fix above;
  `SECURITY.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`; CI `permissions: contents: read`.

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
