# evtlog-triage

Triage Windows Event Logs for security-relevant **sequences**, not single events.

## What

`evtlog-triage` reads Windows Security-log-style events from a JSON or CSV export (the CLI), or —
through the Windows-only library API — from a live channel or an `.evtx` file, and runs a set of
correlation rules over them, producing findings: a rule ID, severity,
time window, the specific events involved, an explanation of what the pattern means, and a
recommended next step.

## Why

A single Event ID 4625 (failed logon) is noise — everyone fat-fingers a password sometimes. Forty
of them from one source in two minutes, followed by a 4624 (successful logon), is a successful
brute-force attack, and that is the thing worth waking someone up for. Most tooling shows you
events. This tool looks for the **patterns across events**, because that is where the signal
actually lives.

## Features

- Nine correlation rules covering credential attacks, privilege abuse, account lifecycle abuse,
  log tampering, and persistence.
- Three output formats: a human-readable table, JSON (for piping into other tooling), and a
  chronological timeline view.
- Filtering: `--since`, `--severity`, `--rules`/`--exclude`, plus rule-relevant context
  (`--expected-admins`, `--business-hours-start`/`--business-hours-end`).
- Configurable exit code threshold (`--fail-on`) for use in CI/scheduled jobs.
- The CLI reads flat JSON and CSV exports on any OS. Live channels and `.evtx` files can be read
  on Windows through the `EvtLogTriage.Windows.WindowsEventReader` library API; the CLI does not
  expose them.
- Exit codes: `0` no finding at/above `--fail-on`, `1` at least one, `2` usage or input error
  (malformed JSON/CSV, unknown option, invalid value).

## Rules reference

| Rule ID | Severity | What it means | Why it matters |
|---|---|---|---|
| `BRUTE-FORCE` | High (Critical if followed by success) | N x 4625 from one source in a window | A burst of failures from one source is automated guessing, not user error. If a 4624 follows, the guess worked. |
| `PASSWORD-SPRAY` | High | One source, many distinct accounts, few attempts each | The inverse shape of brute force. Deliberately stays under per-account lockout thresholds, which is exactly why naive per-account alerting misses it. |
| `OFF-HOURS-LOGON` | Low | 4624 outside configured business hours/days | Not proof of anything by itself, but off-hours activity and time-zone-mismatched attackers show up here. Worth a glance, not a page. |
| `PRIV-ESCALATION` | Medium | 4672 for an account not on the expected-admin list | 4672 is routine for real admins; for anyone else it suggests escalation, a group-membership change, or a compromised elevated account. |
| `ACCOUNT-LIFECYCLE` | Critical | 4720 -> 4732 -> 4726 for the same account in a short window | Routine provisioning doesn't delete an account hours after creating it. This is the create-a-throwaway-admin-and-clean-up-after-yourself shape. |
| `LOG-TAMPERING` | Critical | 1102 (audit log cleared) | There is essentially no routine reason to clear the security log. Always reported at the top severity. |
| `SERVICE-INSTALL` | High | 7045 with a binary path in Temp/AppData/Downloads/ProgramData/Public | Legitimate software installs to Program Files. Malware and lateral-movement tooling installs from writable, unmonitored locations. |
| `EXPLICIT-CRED-BURST` | Medium | A burst of 4648 for one account/source in a window | A single 4648 is routine (runas, scheduled tasks). A burst suggests scripted credential testing or automated lateral movement. |
| `IMPOSSIBLE-TRAVEL` | High | Same account, 4624 from two distinct source addresses within a short window | **Heuristic only** — compares source addresses, not geolocation or network distance. It flags "different address, suspiciously soon," not confirmed impossible travel. Always corroborate before acting. |

Every rule's rationale also lives in its XML doc comment in `src/EvtLogTriage.Core/Rules/`.

## Architecture

```
src/
  EvtLogTriage.Core/       platform-neutral: EventRecord model, rules, engine, readers (JSON/CSV), output
  EvtLogTriage.Windows/    Windows-only: EVTX / live-channel reader ([SupportedOSPlatform("windows")])
  EvtLogTriage.Cli/        the evtlog-triage executable
tests/
  EvtLogTriage.Core.Tests/ xUnit tests (rules, readers, engine, CLI argument parsing, output)
samples/
  sample-security-events.json / .csv   synthetic sample logs used by the CI smoke test
```

All detection and correlation logic operates on the plain `EventRecord` model (event ID,
timestamp, provider, computer, account, source address, level, structured data fields) and has no
dependency on any Windows-only API. That is what makes it testable and runnable on Linux CI.
`EvtLogTriage.Windows` is a thin, optional adapter that turns a live channel or `.evtx` file into
the same `EventRecord` shape using `System.Diagnostics.Eventing.Reader`.

## Platform support

| Component | Linux / macOS | Windows |
|---|---|---|
| Core detection/correlation engine | Yes | Yes |
| JSON reader | Yes | Yes |
| CSV reader | Yes | Yes |
| CLI (`evtlog-triage`) with JSON/CSV input | Yes | Yes |
| Event XML → `EventRecord` mapping (`EventXmlParser`) | Yes | Yes |
| Live event log channel reader (library API only) | No | Yes (not exercised by the test suite) |
| `.evtx` file reader (library API only) | No | Yes (not exercised by the test suite) |

`EvtLogTriage.Windows` builds on any OS (its reference assembly is portable) but its APIs throw at
runtime off Windows, which is why they are gated behind `[SupportedOSPlatform("windows")]`. If you
only have JSON/CSV exports — which is the common case for logs pulled off a machine you don't have
interactive access to — everything works cross-platform.

## Installation

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0). The projects target
`net8.0`; with only a newer .NET runtime installed, run the tests and the CLI with
`DOTNET_ROLL_FORWARD=Major` set in the environment.

```
git clone <this-repo>
cd evtlog-triage
dotnet build -c Release
```

## Usage

```
dotnet run --project src/EvtLogTriage.Cli -c Release -- <input-file> [options]
```

or, after publishing:

```
evtlog-triage <input-file> [options]
```

Options:

```
--format <table|json|timeline>   Output format (default: table)
--reader <json|csv>               Force a reader instead of inferring from file extension
--since <ISO-8601 datetime>       Only consider events at or after this time
--severity <level>                Minimum severity to report (default: Informational)
--fail-on <level>                 Exit non-zero if any finding is at/above this severity (default: High)
--rules <RULE1,RULE2,...>         Only run these rule IDs
--exclude <RULE1,RULE2,...>       Skip these rule IDs
--expected-admins <a,b,...>       Accounts allowed to hold admin privileges (default: none)
--business-hours-start <HH:mm>    Business hours start (default: 08:00)
--business-hours-end <HH:mm>      Business hours end (default: 18:00); must be after the start
                                  (overnight business hours are not supported)
--help                            Show help text
```

Severity levels: `Informational`, `Low`, `Medium`, `High`, `Critical`.

Times: event timestamps and `--since` without an explicit offset are read as UTC. Business hours
are compared against each event's timestamp *as written* (for `...Z` exports, that is UTC), not
against the analyst's or the host's local time zone.

## Input formats

**JSON** — an array (or single object) of events with *flat* fields. Field names are matched
case-insensitively with several common aliases:

```json
[
  { "EventId": 4625, "TimeCreated": "2026-01-05T02:10:00Z", "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "APP-SRV01", "Account": "victim.demo", "SourceAddress": "203.0.113.50", "Level": "Information" }
]
```

Recognized keys: `EventId`/`Id`, `TimeCreated`/`TimeGenerated`, `Provider`/`ProviderName`/`LogName`,
`Computer`/`MachineName`, `Account`/`TargetUserName`/`SubjectUserName`/`UserId`/`AccountName`,
`SourceAddress`/`IpAddress`/`SourceNetworkAddress`, `Level`/`LevelDisplayName`. Anything else on the
object (e.g. `ServiceFileName`, `ServiceName`) is preserved and available to rules that need it.
A `-` (Windows' "no value") or blank account/address is treated as missing.

Raw `Get-WinEvent | ConvertTo-Json` output parses (its `Id`, `TimeCreated`, `ProviderName`,
`MachineName` and `LevelDisplayName` are recognized, including the `/Date(...)/` timestamp form),
but it carries the account and source address only inside the positional `Properties` array and
the `Message` text, which this reader does not decode. With such input the account- and
address-based rules (brute force, spray, impossible travel, privilege escalation, explicit
credentials) cannot fire. Flatten the fields you need into named properties before exporting.

**CSV** — a header row with the same canonical column names (`EventId`, `TimeCreated`, `Provider`,
`Computer`, `Account`, `SourceAddress`, `Level`), the shape you get from
`Get-WinEvent ... | Select-Object ... | Export-Csv`. Any extra column is preserved the same way as
JSON's extra fields. The `#TYPE ...` line that Windows PowerShell 5.1's `Export-Csv` writes before
the header is skipped.

**EVTX / live channel** (Windows only, library API) — via
`EvtLogTriage.Windows.WindowsEventReader.ReadEvtxFile` or `.ReadChannel`. Each record's XML
rendering is mapped by the platform-neutral `EventXmlParser`, which takes the account and source
address from the *named* `EventData` fields for each event ID (`TargetUserName`/`IpAddress` for
logons, `SubjectUserName` for 4672 and 1102, `MemberName` or `MemberSid` for 4732). The mapping is
unit-tested on hand-written XML that follows the documented templates; reading real channels and
`.evtx` files has not been verified on a Windows host. On local groups, 4732 records `MemberName`
as `-`, so `ACCOUNT-LIFECYCLE` can only correlate it with 4720/4726 when the member name is present.

## Examples

```
# Human-readable table, default thresholds
dotnet run --project src/EvtLogTriage.Cli -c Release -- samples/sample-security-events.json

# JSON output, only critical+ findings, piped to jq
dotnet run --project src/EvtLogTriage.Cli -c Release -- samples/sample-security-events.json \
  --format json --severity Critical

# Timeline view of the CSV sample, only brute-force and log-tampering rules
dotnet run --project src/EvtLogTriage.Cli -c Release -- samples/sample-security-events.csv \
  --format timeline --rules BRUTE-FORCE,LOG-TAMPERING

# Treat a known service account as an expected admin
dotnet run --project src/EvtLogTriage.Cli -c Release -- samples/sample-security-events.json \
  --expected-admins svc-admin,root-ops
```

## Testing

```
dotnet test
```

133 xUnit tests cover every rule firing and *not* firing (including plausible false-positive
shapes — three failed logons is not brute force, an admin on the expected list using admin
privileges is not escalation, a 09:00 logon is not off-hours), window-boundary behavior, burst
merging, the JSON/CSV readers and the event-XML mapping (including malformed and hostile input),
output formatting, CLI argument parsing, and CLI exit codes.

## Security

Sample logs in `samples/` use synthetic account names (`victim.demo`, `temp-svc99`, ...) and IP
addresses from the RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24`) — none of it is real traffic or real identities.

This tool only reads and analyzes logs; it takes no remediation action on its own. Treat its
findings as triage input for a human, not as ground truth — in particular, `IMPOSSIBLE-TRAVEL` is
an address-based heuristic, not a geolocation check, and false positives are expected for anyone
behind a rotating egress IP or VPN.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
