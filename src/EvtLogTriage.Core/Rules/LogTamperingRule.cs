using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Flags every audit log clear (1102). There is essentially no routine reason to clear the
/// security audit log; it is one of the strongest single-event indicators of an attacker
/// covering their tracks, so it is always reported at the highest severity.
/// </summary>
public sealed class LogTamperingRule : IDetectionRule
{
    public string RuleId => "LOG-TAMPERING";
    public string Name => "Audit log cleared";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var clears = events.Where(e => e.EventId == EventIds.AuditLogCleared).OrderBy(e => e.TimeCreated);

        foreach (var evt in clears)
        {
            yield return new Finding
            {
                RuleId = RuleId,
                RuleName = Name,
                Severity = Severity.Critical,
                WindowStart = evt.TimeCreated,
                WindowEnd = evt.TimeCreated,
                Events = new[] { evt },
                Summary = $"Security audit log cleared on '{evt.Computer}' by '{evt.Account ?? "(unknown)"}'",
                Explanation = "The security audit log was cleared (Event ID 1102). There is essentially no " +
                    "routine administrative reason to clear this log; it is one of the strongest single-event " +
                    "indicators of an attacker deliberately destroying evidence of prior activity.",
                Recommendation = "Treat as a likely active incident. Immediately review any surviving logs " +
                    "(forwarded/SIEM copies), identify who cleared the log and why, and assume prior compromise " +
                    "until proven otherwise.",
            };
        }
    }
}
