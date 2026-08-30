using EvtLogTriage.Core.Models;
using Xunit;

namespace EvtLogTriage.Core.Tests;

public class TriageEngineTests
{
    [Fact]
    public void Run_FindsLogTamperingByDefault()
    {
        var engine = new TriageEngine();
        var events = new[] { TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator") };

        var findings = engine.Run(events, TriageOptions.Default);

        Assert.Contains(findings, f => f.RuleId == "LOG-TAMPERING");
    }

    [Fact]
    public void Run_FiltersOutEventsBeforeSince()
    {
        var engine = new TriageEngine();
        var events = new[] { TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator") };
        var options = new TriageOptions { Since = TestEvents.Base.AddDays(1) };

        var findings = engine.Run(events, options);

        Assert.Empty(findings);
    }

    [Fact]
    public void Run_IncludesEventsExactlyAtSince()
    {
        var engine = new TriageEngine();
        var events = new[] { TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator") };
        var options = new TriageOptions { Since = TestEvents.Base };

        var findings = engine.Run(events, options);

        Assert.Single(findings);
    }

    [Fact]
    public void Run_RespectsMinimumSeverity()
    {
        var engine = new TriageEngine();
        var events = new[] { TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base, "mallory") };
        var options = new TriageOptions { MinimumSeverity = Severity.High };

        var findings = engine.Run(events, options);

        Assert.Empty(findings); // priv escalation is Medium, filtered out
    }

    [Fact]
    public void Run_IncludeRules_RestrictsToSpecifiedRules()
    {
        var engine = new TriageEngine();
        var events = new[]
        {
            TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator"),
            TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base, "mallory"),
        };
        var options = new TriageOptions { IncludeRules = new HashSet<string> { "LOG-TAMPERING" } };

        var findings = engine.Run(events, options);

        Assert.Single(findings);
        Assert.Equal("LOG-TAMPERING", findings[0].RuleId);
    }

    [Fact]
    public void Run_ExcludeRules_SkipsSpecifiedRules()
    {
        var engine = new TriageEngine();
        var events = new[] { TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator") };
        var options = new TriageOptions { ExcludeRules = new HashSet<string> { "LOG-TAMPERING" } };

        var findings = engine.Run(events, options);

        Assert.Empty(findings);
    }

    [Fact]
    public void Run_SortsFindingsByWindowStart()
    {
        var engine = new TriageEngine();
        var events = new[]
        {
            TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base.AddDays(2), "administrator"),
            TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator"),
        };

        var findings = engine.Run(events, TriageOptions.Default);

        Assert.Equal(2, findings.Count);
        Assert.True(findings[0].WindowStart < findings[1].WindowStart);
    }

    [Fact]
    public void DefaultRules_ContainsAllNineRules()
    {
        var rules = TriageEngine.DefaultRules();

        Assert.Equal(9, rules.Count);
        Assert.Equal(9, rules.Select(r => r.RuleId).Distinct().Count());
    }
}
