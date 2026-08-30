using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class ExplicitCredentialRuleTests
{
    private readonly ExplicitCredentialRule _rule = new();
    private readonly TriageOptions _options = new()
    {
        ExplicitCredentialThreshold = 6,
        ExplicitCredentialWindow = TimeSpan.FromMinutes(5),
    };

    [Fact]
    public void Fires_WhenBurstReachesThreshold()
    {
        var events = Enumerable.Range(0, 6)
            .Select(i => TestEvents.Make(EventIds.ExplicitCredentialLogon, TestEvents.Base.AddSeconds(i * 10), "svc-runner"))
            .ToList();

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.Medium, findings[0].Severity);
    }

    [Fact]
    public void DoesNotFire_ForSingleExplicitCredentialLogon()
    {
        var events = new[] { TestEvents.Make(EventIds.ExplicitCredentialLogon, TestEvents.Base, "svc-runner") };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenBelowThreshold()
    {
        var events = Enumerable.Range(0, 5)
            .Select(i => TestEvents.Make(EventIds.ExplicitCredentialLogon, TestEvents.Base.AddSeconds(i * 10), "svc-runner"))
            .ToList();

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenSpreadAcrossDifferentAccounts()
    {
        var events = Enumerable.Range(0, 6)
            .Select(i => TestEvents.Make(EventIds.ExplicitCredentialLogon, TestEvents.Base.AddSeconds(i * 10), $"user{i}"))
            .ToList();

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenSpanExceedsWindow()
    {
        var events = Enumerable.Range(0, 6)
            .Select(i => TestEvents.Make(EventIds.ExplicitCredentialLogon, TestEvents.Base.AddMinutes(i * 2), "svc-runner"))
            .ToList();

        Assert.Empty(_rule.Evaluate(events, _options));
    }
}
