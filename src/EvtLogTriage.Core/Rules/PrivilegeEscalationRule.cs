using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Flags special-privilege assignment (4672) for accounts not on the configured expected-admin
/// list. 4672 fires whenever an account with admin-equivalent rights logs on; a known admin using
/// admin privileges is expected noise, but the same event for an unexpected account is a strong
/// signal of privilege escalation or a stolen/elevated token.
/// </summary>
public sealed class PrivilegeEscalationRule : IDetectionRule
{
    public string RuleId => "PRIV-ESCALATION";
    public string Name => "Unexpected privileged logon";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var privileged = events.Where(e => e.EventId == EventIds.SpecialPrivilegesAssigned)
            .OrderBy(e => e.TimeCreated);

        foreach (var evt in privileged)
        {
            if (evt.Account is not null && options.ExpectedAdmins.Contains(evt.Account))
            {
                continue;
            }

            yield return new Finding
            {
                RuleId = RuleId,
                RuleName = Name,
                Severity = Severity.Medium,
                WindowStart = evt.TimeCreated,
                WindowEnd = evt.TimeCreated,
                Events = new[] { evt },
                Summary = $"Special privileges assigned to '{evt.Account ?? "(unknown)"}', not on the expected-admin list",
                Explanation = $"Account '{evt.Account ?? "(unknown)"}' was granted special/admin-equivalent " +
                    "privileges (Event ID 4672) on logon, but is not on the configured expected-admin list. " +
                    "This event is routine for known administrators; for anyone else it suggests privilege " +
                    "escalation, an unauthorized group membership change, or use of a compromised elevated account.",
                Recommendation = "Verify whether this account should hold admin rights. If not expected, " +
                    "investigate how it obtained them (recent group membership changes) and revoke if unauthorized.",
            };
        }
    }
}
