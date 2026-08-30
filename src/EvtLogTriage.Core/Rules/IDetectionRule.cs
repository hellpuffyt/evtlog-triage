using System.Collections.Generic;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>A single correlation/detection rule operating over a chronologically-sorted event set.</summary>
public interface IDetectionRule
{
    /// <summary>Stable machine-readable identifier, e.g. "BRUTE-FORCE".</summary>
    string RuleId { get; }

    /// <summary>Human-readable name.</summary>
    string Name { get; }

    /// <summary>
    /// Evaluates the rule against all events (already filtered by --since) and yields zero or more findings.
    /// Events are guaranteed sorted ascending by TimeCreated.
    /// </summary>
    IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options);
}
