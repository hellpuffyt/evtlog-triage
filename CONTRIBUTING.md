# Contributing

Thanks for considering a contribution to evtlog-triage.

## Development environment

The project targets .NET 8. Build and test with the standard SDK tooling:

```
dotnet build -c Release
dotnet test
dotnet format --verify-no-changes
```

`EvtLogTriage.Windows` targets `net8.0-windows` and depends on
`System.Diagnostics.EventLog`; it builds on any OS (the reference assembly is portable) but its
APIs only function at runtime on Windows. `EvtLogTriage.Core`, `EvtLogTriage.Cli`, and the test
suite are fully cross-platform and are what CI exercises on both Linux and Windows.

## Adding a detection rule

1. Implement `IDetectionRule` in `src/EvtLogTriage.Core/Rules/`.
2. Register it in `TriageEngine.DefaultRules()`.
3. Document the rule's rationale in its XML doc comment and in the README's rule reference table.
4. Add tests that cover the rule firing, the rule *not* firing on a plausible false-positive
   shape, and any window-boundary edge cases.
5. Add any new tunable thresholds to `TriageOptions` with a sensible default.

## Style

- `<Nullable>enable</Nullable>` and `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` are on
  for every project; keep the build warning-free rather than suppressing broadly.
- Run `dotnet format` before submitting a change.
- Keep rule logic in the platform-neutral core; anything Windows-only belongs in
  `EvtLogTriage.Windows` behind `[SupportedOSPlatform("windows")]`.

## Reporting issues

Please include a minimal synthetic event sequence (JSON or CSV, using documentation-range IPs and
obviously fake account names) that reproduces the problem.
