using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class PasswordSprayRuleTests
{
    private readonly PasswordSprayRule _rule = new();
    private readonly TriageOptions _options = new()
    {
        SprayDistinctAccountThreshold = 5,
        SprayMaxAttemptsPerAccount = 3,
        SprayWindow = TimeSpan.FromMinutes(10),
    };

    [Fact]
    public void Fires_WhenManyDistinctAccountsFewAttemptsEach()
    {
        var events = Enumerable.Range(0, 5)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 30), $"user{i}", "203.0.113.10"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
        Assert.Equal("PASSWORD-SPRAY", findings[0].RuleId);
    }

    [Fact]
    public void DoesNotFire_WhenBelowDistinctAccountThreshold()
    {
        var events = Enumerable.Range(0, 4)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 30), $"user{i}", "203.0.113.10"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void DoesNotFire_WhenBruteForceShape_ManyAttemptsOnFewAccounts()
    {
        // This is brute force shape (one account hammered), not spray shape.
        var events = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 10), "alice", "203.0.113.10"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void DoesNotFire_WhenEventsHaveNoSourceAddress()
    {
        var events = Enumerable.Range(0, 5)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 30), $"user{i}", null))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void DoesNotFire_WhenOutsideWindow()
    {
        var events = Enumerable.Range(0, 5)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddMinutes(i * 5), $"user{i}", "203.0.113.10"))
            .ToList(); // spans 20 minutes > 10 minute window

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void DoesNotFire_WhenOneAccountExceedsMaxAttempts()
    {
        var events = new List<EventRecord>
        {
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base, "user0", "203.0.113.10"),
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(5), "user0", "203.0.113.10"),
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(10), "user0", "203.0.113.10"),
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(15), "user0", "203.0.113.10"), // 4th attempt exceeds max of 3
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(20), "user1", "203.0.113.10"),
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(25), "user2", "203.0.113.10"),
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(30), "user3", "203.0.113.10"),
            TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(35), "user4", "203.0.113.10"),
        };

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Empty(findings);
    }
}
