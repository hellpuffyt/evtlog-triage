using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class LogTamperingRuleTests
{
    private readonly LogTamperingRule _rule = new();

    [Fact]
    public void Fires_ForEveryAuditLogClear()
    {
        var events = new[] { TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator") };

        var findings = _rule.Evaluate(events, TriageOptions.Default).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.Critical, findings[0].Severity);
    }

    [Fact]
    public void DoesNotFire_ForUnrelatedEvents()
    {
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "administrator") };

        Assert.Empty(_rule.Evaluate(events, TriageOptions.Default));
    }

    [Fact]
    public void ProducesOneFindingPerClearEvent()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator"),
            TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base.AddDays(1), "administrator"),
        };

        var findings = _rule.Evaluate(events, TriageOptions.Default).ToList();

        Assert.Equal(2, findings.Count);
    }
}
