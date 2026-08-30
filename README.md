# evtlog-triage

Triage Windows Event Logs for security-relevant **sequences**, not single events.

## What

`evtlog-triage` reads Windows Security-log-style events (live, from `.evtx`, or from a JSON/CSV
export) and runs a set of correlation rules over them, producing findings: a rule ID, severity,
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
- Reads JSON (`Get-WinEvent | ConvertTo-Json` shape) and CSV (`Export-Csv` shape) exports on any
  OS; optionally reads live channels/`.evtx` files directly on Windows.

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
| Live event log channel reader | No | Yes |
| `.evtx` file reader | No | Yes |

`EvtLogTriage.Windows` builds on any OS (its reference assembly is portable) but its APIs throw at
runtime off Windows, which is why they are gated behind `[SupportedOSPlatform("windows")]`. If you
only have JSON/CSV exports — which is the common case for logs pulled off a machine you don't have
interactive access to — everything works cross-platform.

## Installation

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

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
--business-hours-end <HH:mm>      Business hours end (default: 18:00)
--help                            Show help text
```

Severity levels: `Informational`, `Low`, `Medium`, `High`, `Critical`.

## Input formats

**JSON** — an array (or single object) of events. Field names are matched case-insensitively with
several common aliases, so both a hand-authored flat schema and the shape produced by
`Get-WinEvent | ConvertTo-Json` are accepted:

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

**CSV** — a header row with the same canonical column names (`EventId`, `TimeCreated`, `Provider`,
`Computer`, `Account`, `SourceAddress`, `Level`), the shape you get from
`Get-WinEvent ... | Select-Object ... | Export-Csv`. Any extra column is preserved the same way as
JSON's extra fields.

**EVTX / live channel** (Windows only) — via `EvtLogTriage.Windows.WindowsEventReader.ReadEvtxFile`
or `.ReadChannel`, producing the same `EventRecord` model.

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

90 xUnit tests cover every rule firing and *not* firing (including plausible false-positive
shapes — three failed logons is not brute force, an admin on the expected list using admin
privileges is not escalation, a 09:00 logon is not off-hours), window-boundary behavior, both
readers, output formatting, and CLI argument parsing.

## Security

Sample logs in `samples/` use synthetic account names (`victim.demo`, `temp-svc99`, ...) and IP
addresses from the RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24`) — none of it is real traffic or real identities.

This tool only reads and analyzes logs; it takes no remediation action on its own. Treat its
findings as triage input for a human, not as ground truth — in particular, `IMPOSSIBLE-TRAVEL` is
an address-based heuristic, not a geolocation check, and false positives are expected for anyone
behind a rotating egress IP or VPN.

## License

MIT — see [LICENSE](LICENSE).
