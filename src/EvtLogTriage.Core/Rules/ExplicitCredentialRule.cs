using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Detects bursts of explicit-credential logons (4648) from the same account within a short
/// window. 4648 fires when a process logs on using explicitly supplied credentials (e.g.
/// "runas", scheduled tasks, or credential-stuffing tools) rather than the caller's own token.
/// A single one is routine (RDP with "use different credentials", a service account launcher);
/// a burst suggests scripted credential testing or lateral movement.
/// </summary>
public sealed class ExplicitCredentialRule : IDetectionRule
{
    public string RuleId => "EXPLICIT-CRED-BURST";
    public string Name => "Explicit-credential logon burst";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var explicitLogons = events.Where(e => e.EventId == EventIds.ExplicitCredentialLogon)
            .OrderBy(e => e.TimeCreated).ToList();

        var groups = SlidingWindow.GroupByKey(explicitLogons, e => e.Account ?? e.SourceAddress);

        foreach (var (key, group) in groups)
        {
            group.Sort((a, b) => a.TimeCreated.CompareTo(b.TimeCreated));
            foreach (var burst in SlidingWindow.FindBursts(
                group, options.ExplicitCredentialThreshold, options.ExplicitCredentialWindow))
            {
                yield return new Finding
                {
                    RuleId = RuleId,
                    RuleName = Name,
                    Severity = Severity.Medium,
                    WindowStart = burst[0].TimeCreated,
                    WindowEnd = burst[^1].TimeCreated,
                    Events = burst,
                    Summary = $"{burst.Count} explicit-credential logons for '{key}' within " +
                        $"{options.ExplicitCredentialWindow.TotalMinutes:N0} minutes",
                    Explanation = $"'{key}' was the subject of {burst.Count} explicit-credential logons " +
                        "(Event ID 4648) in a short window. A single explicit-credential logon is routine " +
                        "(runas, scheduled tasks, RDP with alternate credentials); this many in this short a " +
                        "span suggests scripted credential testing, a credential-stuffing tool, or automated " +
                        "lateral movement using harvested credentials.",
                    Recommendation = "Identify the process and destination hosts behind these logons; if not " +
                        "explained by a known automation/service account, treat as potential lateral movement.",
                };
            }
        }
    }
}
