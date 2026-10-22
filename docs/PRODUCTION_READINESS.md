# Production readiness — evtlog-triage

Audit of the `audit/production-readiness` branch. Evidence only; the
classification at the end is a proposal for the maintainer to confirm.

- Tested commit: `1d7b0ab1e712af293e8566ceb57d1820eac93cc0` (this file was
  added in the next commit and changes no code)
- Date: 2026-10-22
- Host: macOS 27 (Apple Silicon), .NET SDK 10.0.402. Only the .NET 10 runtime
  is installed, so the `net8.0` test host and CLI were run with
  `DOTNET_ROLL_FORWARD=Major` (documented in the README). The .NET 8 runtime
  itself was not exercised locally.

## Scope

A CLI plus libraries that correlate Windows Security-log events into findings
(nine rules: brute force, password spray, off-hours logon, privilege
escalation, account lifecycle, log tampering, suspicious service install,
explicit-credential bursts, address-change "impossible travel"). Input: flat
JSON or CSV exports on any OS. A Windows-only library API reads live channels
and `.evtx` files; the CLI does not expose it. Output: table, JSON or
timeline; exit code gated by `--fail-on`.

Architecture: `EvtLogTriage.Core` (model, readers, rules, engine, output;
platform-neutral) ← `EvtLogTriage.Cli`; `EvtLogTriage.Windows` is a thin
`System.Diagnostics.Eventing.Reader` shim that now hands each record's XML to
the platform-neutral `EventXmlParser`.

## Platforms and prerequisites

- .NET 8 SDK (or a newer SDK with `DOTNET_ROLL_FORWARD=Major`). Verified
  locally on macOS arm64.
- CI: tests on ubuntu-latest and windows-latest, a Release build with
  `dotnet format --verify-no-changes`, and a CLI smoke job on the samples.

## What needs a real Windows host (unverified here)

- `WindowsEventReader.ReadChannel` / `ReadEvtxFile`: never executed. Only the
  XML → `EventRecord` mapping they delegate to is tested, on hand-written
  XML that follows Microsoft's documented security-auditing templates, not
  on XML captured from a real host.
- Whether real `Get-WinEvent | Select-Object | Export-Csv` and Windows
  PowerShell 5.1 exports match the documented shapes: reasoned from
  documentation, not run (PowerShell is not available here).
- The windows-latest CI leg on this branch (pending until pushed).

## Clean-clone verification

Fresh clone of the branch into an empty scratch directory, README followed
literally (with `DOTNET_ROLL_FORWARD=Major` exported, as the README now
documents for hosts without the .NET 8 runtime):

| Command | Exit | Result |
|---|---|---|
| `dotnet build -c Release` | 0 | 0 warnings, 0 errors (warnings are errors; includes the Windows project) |
| `dotnet test` | 0 | 133 passed, 0 failed, 0 skipped |
| `dotnet run --project src/EvtLogTriage.Cli -c Release -- samples/sample-security-events.json` | 1 | findings printed; 1 = a finding at/above the default `--fail-on High` |
| `… --format json --severity Critical` | 1 | JSON |
| `… samples/sample-security-events.csv --format timeline --rules BRUTE-FORCE,LOG-TAMPERING` | 1 | timeline |
| `… --expected-admins svc-admin,root-ops` | 1 | table |
| `… --help` | 0 | help |
| `dotnet format --verify-no-changes` | 0 | clean |

All nine rules fire on `samples/sample-security-events.json`
(`--format json --expected-admins nobody`: 2 off-hours, 1 each of the others).

## Commands executed (working clone)

| Command | Exit | Outcome |
|---|---|---|
| `dotnet build -c Release` (baseline `a6ef20a`) | 0 | 0 warnings |
| `dotnet test -c Release` (baseline, no roll-forward) | 1 | test host could not start: .NET 8 runtime missing (environment, not a code defect) |
| `DOTNET_ROLL_FORWARD=Major dotnet test -c Release` (baseline) | 0 | 90 passed, 0 failed, 0 skipped |
| CLI probe with malformed inputs (baseline) | 134 | unhandled exceptions for truncated/empty JSON, `[1,2]`, `"/Date(123"`, `--business-hours-start 25:99`, `--bogus` |
| new regression tests against baseline sources (`git stash` of `src/`) | 1 | 26 of the new tests fail, 95 pass |
| `DOTNET_ROLL_FORWARD=Major dotnet test -c Release` (after) | 0 | 133 passed, 0 failed, 0 skipped |
| `dotnet format --verify-no-changes` | 0 | clean |
| `dotnet list package --vulnerable --include-transitive` | 0 | no vulnerable packages in any project |
| history secret scan (`git grep` over every commit) | — | no hits |

## Bugs found and fixed

| # | Bug | Fix | Regression test |
|---|---|---|---|
| 1 | Malformed/empty JSON, non-object array elements, `"/Date(123"`, unknown options and invalid option values crashed the CLI with an unhandled exception (exit 134 on macOS). | Readers raise `InvalidDataException`; `Program` maps input/usage errors to exit 2. | `JsonReader_MalformedInput_*`, `Program_MalformedInputExitsTwoInsteadOfCrashing`, `Program_UnknownOptionExitsTwoInsteadOfCrashing` |
| 2 | `--severity 42` accepted as an undefined severity; `--business-hours-start 9` read as 9 *days*; end ≤ start marked everything off-hours; a second input file silently ignored. | Strict parsing and validation. | `CliArguments_RejectsInvalidValues` (9 cases), `…BusinessHoursThatEndBeforeTheyStart`, `…RejectsASecondInputFile` |
| 3 | `--since` without an offset was parsed in local time and the current culture, while event timestamps are UTC. | Invariant culture, UTC assumed. | `CliArguments_SinceWithoutOffsetIsUtc` |
| 4 | Bursts were cut at exactly the threshold: 40 failures in 2 min became four findings of "10 failed logons". | A burst extends to every event within the window of its first event. | `BruteForce_FortyFailuresInTwoMinutes_IsOneFindingWithAllForty`, `…BurstsInSeparateWindows_StaySeparate` |
| 5 | `-` (Windows "no value", e.g. `IpAddress` on local logons) and blank values were real grouping keys, merging unrelated accounts into one brute-force source. | Normalized to null in every reader. | `BruteForce_DashPlaceholderAddressesFromDifferentAccountsAreNotMerged`, `JsonReader_NormalizesDashAndBlankIdentities` |
| 6 | The EVTX/live reader took account/address from positions 5/18 for every event: wrong for 4625 (18 = `ProcessName`), 4672, 4732, 1102; 7045's `ImagePath` was stored as `Data1` so `SERVICE-INSTALL` could never fire. | New `EventXmlParser` maps by `EventData` field name per event ID; the Windows shim uses it. Hostile XML (DTD) is refused. | `EventXmlParserTests` (12) |
| 7 | Object-valued account fields (e.g. `UserId` SID object from `Get-WinEvent | ConvertTo-Json`) became the account as raw JSON. | Ignored. | covered by reader tests |
| 8 | Windows PowerShell 5.1 `Export-Csv` `#TYPE` line was taken as the header (every row then "missing EventId"). | Skipped. | `CsvReader_SkipsWindowsPowerShellTypeLine` |
| 9 | README claimed the tool reads live/`.evtx` logs and accepts the `Get-WinEvent | ConvertTo-Json` shape. | README corrected: CLI = JSON/CSV; EVTX/live = Windows library API, unverified; raw `Get-WinEvent` JSON lacks the account/address fields most rules need. | — |

## Security review

- No network access, no remediation actions, no process execution.
- XML: DTD processing prohibited, no resolver (test with an external-entity
  payload). JSON: `System.Text.Json` defaults (depth limit 64).
- Input files are read whole into memory; very large exports need
  correspondingly large memory (not bounded; documented here).
- `IMPOSSIBLE-TRAVEL` emits one finding per differing address pair inside the
  window, so a rotating-IP account can produce many findings (noise, not a
  safety issue).
- CI now declares `permissions: contents: read`; action references are tag
  pins (`@v4`), left as they were. `SECURITY.md` added.

## Limitations and unresolved risks

- Windows-only reading paths are unverified (see above).
- `ACCOUNT-LIFECYCLE` on local groups: 4732 records `MemberName` as `-`, so
  the parser falls back to `MemberSid`, which does not match the name-based
  4720/4726 account; correlation then needs a domain member name.
- Business hours are evaluated in each timestamp's own offset (UTC for `Z`
  exports); overnight business hours are not supported.
- A burst longer than the window is still reported as consecutive window-sized
  findings.

## CI status

- Default branch (`a6ef20a`): success.
- Audit branch: pending until pushed.

## Acceptance checklist

| Item | Expected behavior | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| Build | warning-free Release build incl. Windows project | `dotnet build -c Release` | pass | 0 warnings | csproj |
| Tests | all pass | `dotnet test` | pass | 133/133 | tests/ |
| Every rule fires on its pattern and not on near misses | per-rule positive/negative fixtures | `Rules/*Tests` | pass | — | src/…/Rules |
| Burst volume | one 40-event burst is one finding of 40 | `BruteForce_FortyFailures…` | pass | 40 events | bug 4 |
| Bad input | malformed JSON/CSV/options exit 2 with a message | `Program_*`, CLI probe | pass | exit 2 | bugs 1, 2 |
| Windows field mapping | account/address by field name per event ID | `EventXmlParserTests` | pass (synthetic XML) | — | bug 6 |
| Samples | all nine rules fire on the JSON sample | CLI `--format json` | pass | 9 rules | samples/ |
| Format | `dotnet format --verify-no-changes` | CLI | pass | clean | CI |
| Dependencies | no known vulnerable packages | `dotnet list package --vulnerable --include-transitive` | pass | none | csproj |
| Live/.evtx reading | reads real Windows logs | needs Windows | not run | — | WindowsEventReader |

## Classification proposal

**Partially Verified**: the platform-neutral engine, readers, CLI and the
event-XML mapping are tested on synthetic fixtures and pass from a clean clone.
Reading live channels and `.evtx` files, real PowerShell export shapes, the
.NET 8 runtime itself and the windows-latest CI leg have not been exercised.
