using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;

namespace EvtLogTriage.Core;

/// <summary>Runs the registered detection rules over a set of events and returns findings.</summary>
public sealed class TriageEngine
{
    private readonly IReadOnlyList<IDetectionRule> _rules;

    public TriageEngine(IEnumerable<IDetectionRule>? rules = null)
    {
        _rules = (rules ?? DefaultRules()).ToList();
    }

    /// <summary>The rules that ship with the engine, in a stable order.</summary>
    public static IReadOnlyList<IDetectionRule> DefaultRules() => new IDetectionRule[]
    {
        new BruteForceRule(),
        new PasswordSprayRule(),
        new OffHoursLogonRule(),
        new PrivilegeEscalationRule(),
        new AccountLifecycleRule(),
        new LogTamperingRule(),
        new ServiceInstallRule(),
        new ExplicitCredentialRule(),
        new ImpossibleTravelRule(),
    };

    public IReadOnlyList<IDetectionRule> Rules => _rules;

    /// <summary>Runs the applicable rules and returns findings, sorted by window start.</summary>
    public IReadOnlyList<Finding> Run(IEnumerable<EventRecord> events, TriageOptions options)
    {
        var sorted = events
            .Where(e => options.Since is null || e.TimeCreated >= options.Since)
            .OrderBy(e => e.TimeCreated)
            .ToList();

        var applicableRules = _rules.Where(r => IsRuleSelected(r.RuleId, options)).ToList();

        var findings = new List<Finding>();
        foreach (var rule in applicableRules)
        {
            findings.AddRange(rule.Evaluate(sorted, options));
        }

        return findings
            .Where(f => f.Severity >= options.MinimumSeverity)
            .OrderBy(f => f.WindowStart)
            .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsRuleSelected(string ruleId, TriageOptions options)
    {
        if (options.IncludeRules is { Count: > 0 } include && !include.Contains(ruleId))
        {
            return false;
        }

        return !options.ExcludeRules.Contains(ruleId);
    }
}
