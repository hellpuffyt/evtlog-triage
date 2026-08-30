using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class ImpossibleTravelRuleTests
{
    private readonly ImpossibleTravelRule _rule = new();
    private readonly TriageOptions _options = new() { ImpossibleTravelWindow = TimeSpan.FromMinutes(15) };

    [Fact]
    public void Fires_ForDifferentSourcesWithinWindow()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "alice", "203.0.113.5"),
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base.AddMinutes(5), "alice", "198.51.100.9"),
        };

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void DoesNotFire_ForSameSourceRepeatedLogons()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "alice", "203.0.113.5"),
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base.AddMinutes(5), "alice", "203.0.113.5"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenOutsideWindow()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "alice", "203.0.113.5"),
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base.AddMinutes(20), "alice", "198.51.100.9"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_ForDifferentAccounts()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "alice", "203.0.113.5"),
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base.AddMinutes(5), "bob", "198.51.100.9"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenSourceAddressMissing()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "alice", null),
            TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base.AddMinutes(5), "alice", "198.51.100.9"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }
}
