using System.Collections.Generic;
using System.Linq;

namespace EvtLogTriage.Core.Models;

/// <summary>A single correlated detection produced by a rule.</summary>
public sealed class Finding
{
    /// <summary>Stable machine-readable rule identifier, e.g. "BRUTE-FORCE".</summary>
    public required string RuleId { get; init; }

    /// <summary>Human-readable rule name, e.g. "Brute-force logon attempts".</summary>
    public required string RuleName { get; init; }

    public required Severity Severity { get; init; }

    public required DateTimeOffset WindowStart { get; init; }

    public required DateTimeOffset WindowEnd { get; init; }

    /// <summary>The correlated events that make up this finding, in chronological order.</summary>
    public required IReadOnlyList<EventRecord> Events { get; init; }

    /// <summary>One-line summary suitable for a table row.</summary>
    public required string Summary { get; init; }

    /// <summary>What this pattern means and why it matters.</summary>
    public required string Explanation { get; init; }

    /// <summary>Recommended next step for a responder.</summary>
    public required string Recommendation { get; init; }

    /// <summary>Convenience: the distinct event IDs involved.</summary>
    public IReadOnlyList<int> EventIds => Events.Select(e => e.EventId).Distinct().OrderBy(i => i).ToList();
}
