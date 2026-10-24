# Security policy

## Supported versions

Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please report security issues privately through GitHub:
https://github.com/hellpuffyt/evtlog-triage/security/advisories/new

Do not open a public issue for a vulnerability, and do not attach real event logs: they contain
account names, host names and addresses. Reduce the problem to a synthetic sample instead.

## Scope

evtlog-triage reads local JSON/CSV exports (or, through the Windows library API, local event
logs) and prints findings; it makes no network calls and takes no remediation action. In scope:
crashes or unbounded resource use on crafted input, XML/JSON parsing issues, and detection logic
that can be trivially evaded in a way the README does not already document.
