using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Flags the same account logging on successfully (4624) from two distinct source addresses
/// within a short window. This is a coarse "impossible travel" heuristic based purely on
/// source addresses seen in the log, NOT geolocation or distance calculation: it cannot tell
/// you the two addresses are actually far apart, only that they are different. Treat findings
/// as a prompt to look closer, not as proof of geographic impossibility.
/// </summary>
public sealed class ImpossibleTravelRule : IDetectionRule
{
    public string RuleId => "IMPOSSIBLE-TRAVEL";
    public string Name => "Multiple source addresses for one account";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var logons = events
            .Where(e => e.EventId == EventIds.SuccessfulLogon && e.Account is not null && e.SourceAddress is not null)
            .OrderBy(e => e.TimeCreated).ToList();

        var byAccount = SlidingWindow.GroupByKey(logons, e => e.Account);

        foreach (var (account, group) in byAccount)
        {
            group.Sort((a, b) => a.TimeCreated.CompareTo(b.TimeCreated));

            for (var i = 0; i < group.Count; i++)
            {
                for (var j = i + 1; j < group.Count; j++)
                {
                    var gap = group[j].TimeCreated - group[i].TimeCreated;
                    if (gap > options.ImpossibleTravelWindow)
                    {
                        break;
                    }

                    if (!string.Equals(group[i].SourceAddress, group[j].SourceAddress, StringComparison.OrdinalIgnoreCase))
                    {
                        yield return new Finding
                        {
                            RuleId = RuleId,
                            RuleName = Name,
                            Severity = Severity.High,
                            WindowStart = group[i].TimeCreated,
                            WindowEnd = group[j].TimeCreated,
                            Events = new[] { group[i], group[j] },
                            Summary = $"'{account}' logged on from '{group[i].SourceAddress}' then " +
                                $"'{group[j].SourceAddress}' within {gap.TotalMinutes:N1} minutes",
                            Explanation = $"Account '{account}' had successful logons from two different " +
                                $"source addresses ('{group[i].SourceAddress}' and '{group[j].SourceAddress}') " +
                                $"only {gap.TotalMinutes:N1} minutes apart. This heuristic compares source " +
                                "addresses only, not geolocation or network distance, so it cannot confirm the " +
                                "two logons were geographically impossible - only that they came from different " +
                                "addresses in quick succession, which warrants a closer look.",
                            Recommendation = "Correlate both addresses with expected locations/VPN egress IPs " +
                                "for this user. If neither is expected, treat as likely credential sharing or " +
                                "compromise and verify with the account owner.",
                        };
                    }
                }
            }
        }
    }
}
