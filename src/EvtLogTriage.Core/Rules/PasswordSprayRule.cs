using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Detects password spraying: one source attempting logons against many distinct accounts,
/// each only a few times, within a window. This is the inverse shape of brute force (many
/// attempts against one account) and is designed to stay under per-account lockout thresholds,
/// which is exactly why it is commonly missed by naive per-account alerting.
/// </summary>
public sealed class PasswordSprayRule : IDetectionRule
{
    public string RuleId => "PASSWORD-SPRAY";
    public string Name => "Password spray";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var failed = events.Where(e => e.EventId == EventIds.FailedLogon && e.SourceAddress is not null)
            .OrderBy(e => e.TimeCreated).ToList();

        var bySource = SlidingWindow.GroupByKey(failed, e => e.SourceAddress);

        foreach (var (source, group) in bySource)
        {
            group.Sort((a, b) => a.TimeCreated.CompareTo(b.TimeCreated));

            // Slide a window across this source's attempts and look for a point where enough
            // distinct accounts have been touched, each with few attempts.
            var left = 0;
            for (var right = 0; right < group.Count; right++)
            {
                while (group[right].TimeCreated - group[left].TimeCreated > options.SprayWindow)
                {
                    left++;
                }

                var slice = group.GetRange(left, right - left + 1);
                var byAccount = slice.Where(e => e.Account is not null)
                    .GroupBy(e => e.Account!, StringComparer.OrdinalIgnoreCase).ToList();

                var distinctAccounts = byAccount.Count;
                var maxAttempts = byAccount.Count == 0 ? 0 : byAccount.Max(g => g.Count());

                if (distinctAccounts >= options.SprayDistinctAccountThreshold &&
                    maxAttempts <= options.SprayMaxAttemptsPerAccount)
                {
                    yield return new Finding
                    {
                        RuleId = RuleId,
                        RuleName = Name,
                        Severity = Severity.High,
                        WindowStart = slice[0].TimeCreated,
                        WindowEnd = slice[^1].TimeCreated,
                        Events = slice,
                        Summary = $"'{source}' attempted logons against {distinctAccounts} distinct accounts " +
                            $"(<= {maxAttempts} attempts each)",
                        Explanation = $"Source '{source}' made failed logon attempts against {distinctAccounts} " +
                            $"different accounts, with no account seeing more than {maxAttempts} attempts, all " +
                            $"within {options.SprayWindow.TotalMinutes:N0} minutes. This low-and-slow, wide " +
                            "fan-out pattern is characteristic of password spraying, which deliberately stays " +
                            "under per-account lockout thresholds to avoid detection.",
                        Recommendation = "Block the source, check whether any of the targeted accounts share a " +
                            "common weak or seasonal password, and review conditional access / lockout policy " +
                            "for gaps that allow low-volume-per-account attacks to go unnoticed.",
                    };

                    left = right + 1;
                }
            }
        }
    }
}
