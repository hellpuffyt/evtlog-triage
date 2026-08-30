using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Detects the "create-abuse-delete" pattern: an account created (4720), added to an admin
/// group (4732), and deleted (4726) again, all within a short window. Legitimate account
/// provisioning does not usually delete the account within hours; this shape is how an
/// attacker plants a throwaway privileged account, uses it, and cleans up after itself.
/// </summary>
public sealed class AccountLifecycleRule : IDetectionRule
{
    public string RuleId => "ACCOUNT-LIFECYCLE";
    public string Name => "Account create-escalate-delete";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var created = events.Where(e => e.EventId == EventIds.UserAccountCreated).ToList();
        var addedToGroup = events.Where(e => e.EventId == EventIds.MemberAddedToSecurityGroup).ToList();
        var deleted = events.Where(e => e.EventId == EventIds.UserAccountDeleted).ToList();

        foreach (var createEvt in created)
        {
            if (createEvt.Account is null)
            {
                continue;
            }

            var windowEnd = createEvt.TimeCreated + options.AccountLifecycleWindow;

            var groupAdd = addedToGroup
                .Where(e => string.Equals(e.Account, createEvt.Account, StringComparison.OrdinalIgnoreCase))
                .Where(e => e.TimeCreated >= createEvt.TimeCreated && e.TimeCreated <= windowEnd)
                .OrderBy(e => e.TimeCreated)
                .FirstOrDefault();

            if (groupAdd is null)
            {
                continue;
            }

            var deleteEvt = deleted
                .Where(e => string.Equals(e.Account, createEvt.Account, StringComparison.OrdinalIgnoreCase))
                .Where(e => e.TimeCreated >= groupAdd.TimeCreated && e.TimeCreated <= windowEnd)
                .OrderBy(e => e.TimeCreated)
                .FirstOrDefault();

            if (deleteEvt is null)
            {
                continue;
            }

            var chain = new[] { createEvt, groupAdd, deleteEvt };

            yield return new Finding
            {
                RuleId = RuleId,
                RuleName = Name,
                Severity = Severity.Critical,
                WindowStart = createEvt.TimeCreated,
                WindowEnd = deleteEvt.TimeCreated,
                Events = chain,
                Summary = $"Account '{createEvt.Account}' created, granted admin rights, and deleted within " +
                    $"{(deleteEvt.TimeCreated - createEvt.TimeCreated).TotalMinutes:N0} minutes",
                Explanation = $"Account '{createEvt.Account}' was created (4720), added to a privileged group " +
                    "(4732), and then deleted (4726), all within " +
                    $"{options.AccountLifecycleWindow.TotalHours:N0} hours. Routine provisioning does not " +
                    "usually delete an account within hours of creating it; this create-escalate-delete shape " +
                    "is a common pattern for a throwaway account planted, used for privileged access, and " +
                    "removed to cover tracks.",
                Recommendation = "Identify who created and deleted the account, review what actions it " +
                    "performed while it existed, and confirm this matches an approved, documented process.",
            };
        }
    }
}
