using System.Collections.Generic;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core;

/// <summary>Tunable thresholds and context used by detection rules.</summary>
public sealed class TriageOptions
{
    /// <summary>Only events at or after this time are considered. Null means no lower bound.</summary>
    public DateTimeOffset? Since { get; init; }

    /// <summary>Only findings at or above this severity are returned.</summary>
    public Severity MinimumSeverity { get; init; } = Severity.Informational;

    /// <summary>Rule IDs to run. Null/empty means "all registered rules".</summary>
    public IReadOnlySet<string>? IncludeRules { get; init; }

    /// <summary>Rule IDs to skip, applied after IncludeRules.</summary>
    public IReadOnlySet<string> ExcludeRules { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // --- Brute force ---
    public int BruteForceThreshold { get; init; } = 10;
    public TimeSpan BruteForceWindow { get; init; } = TimeSpan.FromMinutes(5);

    // --- Password spray ---
    public int SprayDistinctAccountThreshold { get; init; } = 5;
    public int SprayMaxAttemptsPerAccount { get; init; } = 3;
    public TimeSpan SprayWindow { get; init; } = TimeSpan.FromMinutes(10);

    // --- Off-hours ---
    public TimeSpan BusinessHoursStart { get; init; } = TimeSpan.FromHours(8);
    public TimeSpan BusinessHoursEnd { get; init; } = TimeSpan.FromHours(18);
    public IReadOnlySet<DayOfWeek> BusinessDays { get; init; } = new HashSet<DayOfWeek>
    {
        DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday,
    };

    // --- Privilege escalation ---
    public IReadOnlySet<string> ExpectedAdmins { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // --- Account lifecycle (create -> admin -> delete abuse) ---
    public TimeSpan AccountLifecycleWindow { get; init; } = TimeSpan.FromHours(24);

    // --- Explicit credential bursts (4648) ---
    public int ExplicitCredentialThreshold { get; init; } = 6;
    public TimeSpan ExplicitCredentialWindow { get; init; } = TimeSpan.FromMinutes(5);

    // --- Impossible travel ---
    public TimeSpan ImpossibleTravelWindow { get; init; } = TimeSpan.FromMinutes(15);

    // --- Service installation ---
    public IReadOnlyList<string> SuspiciousServicePathFragments { get; init; } = new[]
    {
        "\\temp\\", "\\tmp\\", "/tmp/", "\\appdata\\local\\temp", "\\users\\public\\",
        "\\programdata\\", "\\downloads\\", "\\windows\\temp\\",
    };

    /// <summary>Default options with no rule filtering.</summary>
    public static TriageOptions Default { get; } = new();
}
