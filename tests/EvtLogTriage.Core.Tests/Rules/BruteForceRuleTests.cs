using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class BruteForceRuleTests
{
    private readonly BruteForceRule _rule = new();
    private readonly TriageOptions _options = new() { BruteForceThreshold = 10, BruteForceWindow = TimeSpan.FromMinutes(5) };

    [Fact]
    public void Fires_WhenThresholdReachedWithinWindow()
    {
        var events = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "alice", "203.0.113.5"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
        Assert.Equal("BRUTE-FORCE", findings[0].RuleId);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void DoesNotFire_WhenBelowThreshold_ThreeFailedLogonsIsNotBruteForce()
    {
        var events = Enumerable.Range(0, 3)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "alice", "203.0.113.5"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void DoesNotFire_WhenAttemptsSpreadAcrossDistinctSources_BelowThresholdEach()
    {
        var events = new List<EventRecord>();
        for (var i = 0; i < 9; i++)
        {
            events.Add(TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 5), "alice", "203.0.113.5"));
        }

        events.Add(TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(50), "alice", "203.0.113.9"));

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void Fires_WhenAllEventsExactlyAtWindowBoundary()
    {
        var events = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 30), "alice", "203.0.113.5"))
            .ToList(); // spans exactly 270s < 300s window

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
    }

    [Fact]
    public void DoesNotFire_WhenSpanExceedsWindow()
    {
        var events = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 60), "alice", "203.0.113.5"))
            .ToList(); // spans 540s > 300s window, so no 10-event window fits

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void EscalatesToCritical_WhenSuccessfulLogonFollowsBurst()
    {
        var events = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "alice", "203.0.113.5"))
            .ToList();
        events.Add(TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base.AddSeconds(100), "alice", "203.0.113.5"));

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.Critical, findings[0].Severity);
        Assert.Contains(findings[0].Events, e => e.EventId == EventIds.SuccessfulLogon);
    }

    [Fact]
    public void DoesNotEscalate_WhenNoSuccessFollows()
    {
        var events = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "alice", "203.0.113.5"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void GroupsIndependentlyBySource()
    {
        var events = new List<EventRecord>();
        events.AddRange(Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "alice", "203.0.113.5")));
        events.AddRange(Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "bob", "198.51.100.7")));

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Equal(2, findings.Count);
    }
}
