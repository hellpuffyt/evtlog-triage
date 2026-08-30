using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Detects a burst of failed logons (4625) from a single source within a short window.
/// A handful of failed logons is normal user error; a rapid burst from one source is an
/// automated guessing attempt. If a successful logon (4624) for the same account follows
/// within the same window, the burst escalates from High to Critical because the attack worked.
/// </summary>
public sealed class BruteForceRule : IDetectionRule
{
    public string RuleId => "BRUTE-FORCE";
    public string Name => "Brute-force logon attempts";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var failed = events.Where(e => e.EventId == EventIds.FailedLogon).OrderBy(e => e.TimeCreated).ToList();
        var groups = SlidingWindow.GroupByKey(failed, e => e.SourceAddress ?? e.Account);

        foreach (var (source, group) in groups)
        {
            group.Sort((a, b) => a.TimeCreated.CompareTo(b.TimeCreated));
            foreach (var burst in SlidingWindow.FindBursts(group, options.BruteForceThreshold, options.BruteForceWindow))
            {
                var windowStart = burst[0].TimeCreated;
                var windowEnd = burst[^1].TimeCreated;

                // Did a success follow, for one of the targeted accounts, within the window (extended
                // slightly to allow the success to land just after the last failure)?
                var accountsTargeted = burst.Select(e => e.Account).Where(a => !string.IsNullOrWhiteSpace(a))
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);

                var followingSuccess = events
                    .Where(e => e.EventId == EventIds.SuccessfulLogon)
                    .Where(e => (e.SourceAddress ?? e.Account) is { } k && string.Equals(k, source, StringComparison.OrdinalIgnoreCase))
                    .Where(e => e.TimeCreated >= windowStart && e.TimeCreated <= windowEnd + options.BruteForceWindow)
                    .Where(e => e.Account is null || accountsTargeted.Count == 0 || accountsTargeted.Contains(e.Account))
                    .OrderBy(e => e.TimeCreated)
                    .FirstOrDefault();

                var allEvents = burst.ToList();
                var severity = Severity.High;
                string explanation = $"{burst.Count} failed logon attempts (Event ID 4625) arrived from " +
                    $"'{source}' within {FormatWindow(windowStart, windowEnd)}. A single failed logon is " +
                    "routine user error; this volume in this short a span is consistent with automated " +
                    "credential guessing against one or more accounts.";
                string recommendation = "Block or rate-limit the source, verify no successful logon occurred " +
                    "for the targeted accounts, and force a password reset if compromise is suspected.";

                if (followingSuccess is not null)
                {
                    allEvents.Add(followingSuccess);
                    allEvents = allEvents.OrderBy(e => e.TimeCreated).ToList();
                    severity = Severity.Critical;
                    explanation += $" A successful logon (Event ID 4624) for account '{followingSuccess.Account}' " +
                        "followed the burst, indicating the guessing attempt succeeded.";
                    recommendation = "Treat as an active compromise: disable or reset the affected account " +
                        "immediately, terminate its sessions, and investigate subsequent activity from it.";
                }

                yield return new Finding
                {
                    RuleId = RuleId,
                    RuleName = Name,
                    Severity = severity,
                    WindowStart = windowStart,
                    WindowEnd = allEvents[^1].TimeCreated,
                    Events = allEvents,
                    Summary = followingSuccess is null
                        ? $"{burst.Count} failed logons from '{source}' in {FormatWindow(windowStart, windowEnd)}"
                        : $"{burst.Count} failed logons from '{source}' followed by a successful logon (account compromised)",
                    Explanation = explanation,
                    Recommendation = recommendation,
                };
            }
        }
    }

    private static string FormatWindow(DateTimeOffset start, DateTimeOffset end) =>
        $"{(end - start).TotalSeconds:N0}s";
}
