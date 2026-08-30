using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class OffHoursLogonRuleTests
{
    private readonly OffHoursLogonRule _rule = new();
    private readonly TriageOptions _options = new()
    {
        BusinessHoursStart = TimeSpan.FromHours(8),
        BusinessHoursEnd = TimeSpan.FromHours(18),
    };

    // TestEvents.Base is Monday 2026-03-02 09:00:00Z

    [Fact]
    public void DoesNotFire_ForLogonAt0900_WithinBusinessHours()
    {
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "alice") };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void Fires_ForLogonBeforeBusinessHoursStart()
    {
        var time = TestEvents.Base.Date + TimeSpan.FromHours(6);
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, new DateTimeOffset(time, TimeSpan.Zero), "alice") };

        Assert.Single(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void Fires_ForLogonAtOrAfterBusinessHoursEnd()
    {
        var time = new DateTimeOffset(TestEvents.Base.Date + TimeSpan.FromHours(18), TimeSpan.Zero);
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, time, "alice") };

        Assert.Single(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_AtExactBusinessHoursStartBoundary()
    {
        var time = new DateTimeOffset(TestEvents.Base.Date + TimeSpan.FromHours(8), TimeSpan.Zero);
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, time, "alice") };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_OneSecondBeforeBusinessHoursEnd()
    {
        var time = new DateTimeOffset(TestEvents.Base.Date + TimeSpan.FromHours(18) - TimeSpan.FromSeconds(1), TimeSpan.Zero);
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, time, "alice") };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void Fires_OnWeekendEvenDuringDaytimeHours()
    {
        // 2026-03-07 is a Saturday
        var time = new DateTimeOffset(2026, 3, 7, 10, 0, 0, TimeSpan.Zero);
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, time, "alice") };

        Assert.Single(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void IgnoresNonLogonEvents()
    {
        var time = TestEvents.Base.Date + TimeSpan.FromHours(3);
        var events = new[] { TestEvents.Make(EventIds.FailedLogon, new DateTimeOffset(time, TimeSpan.Zero), "alice") };

        Assert.Empty(_rule.Evaluate(events, _options));
    }
}
