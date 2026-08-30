using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Flags successful logons (4624) outside configured business hours/days for the account.
/// A single off-hours logon is not automatically malicious, but it is worth a human glance,
/// especially for accounts that never normally authenticate outside the window.
/// </summary>
public sealed class OffHoursLogonRule : IDetectionRule
{
    public string RuleId => "OFF-HOURS-LOGON";
    public string Name => "Off-hours logon";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var logons = events.Where(e => e.EventId == EventIds.SuccessfulLogon).OrderBy(e => e.TimeCreated);

        foreach (var logon in logons)
        {
            if (!IsOffHours(logon.TimeCreated, options))
            {
                continue;
            }

            yield return new Finding
            {
                RuleId = RuleId,
                RuleName = Name,
                Severity = Severity.Low,
                WindowStart = logon.TimeCreated,
                WindowEnd = logon.TimeCreated,
                Events = new[] { logon },
                Summary = $"Off-hours logon by '{logon.Account}' at {logon.TimeCreated:yyyy-MM-dd HH:mm} " +
                    $"({logon.TimeCreated.DayOfWeek})",
                Explanation = $"Account '{logon.Account}' successfully logged on at " +
                    $"{logon.TimeCreated:yyyy-MM-dd HH:mm} ({logon.TimeCreated.DayOfWeek}), outside the " +
                    $"configured business hours of {options.BusinessHoursStart:hh\\:mm}-" +
                    $"{options.BusinessHoursEnd:hh\\:mm} on {string.Join(", ", options.BusinessDays)}. " +
                    "Legitimate off-hours work happens, but this pattern is also how after-hours account " +
                    "abuse and time-zone-mismatched attackers show up in logs.",
                Recommendation = "Confirm the logon was expected (on-call work, travel, scheduled job) with " +
                    "the account owner or their manager; if unexpected, treat as a potential compromise.",
            };
        }
    }

    private static bool IsOffHours(DateTimeOffset time, TriageOptions options)
    {
        if (!options.BusinessDays.Contains(time.DayOfWeek))
        {
            return true;
        }

        var timeOfDay = time.TimeOfDay;
        return timeOfDay < options.BusinessHoursStart || timeOfDay >= options.BusinessHoursEnd;
    }
}
