using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class AccountLifecycleRuleTests
{
    private readonly AccountLifecycleRule _rule = new();
    private readonly TriageOptions _options = new() { AccountLifecycleWindow = TimeSpan.FromHours(24) };

    [Fact]
    public void Fires_ForCreateEscalateDeleteWithinWindow()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.UserAccountCreated, TestEvents.Base, "temp01"),
            TestEvents.Make(EventIds.MemberAddedToSecurityGroup, TestEvents.Base.AddMinutes(5), "temp01"),
            TestEvents.Make(EventIds.UserAccountDeleted, TestEvents.Base.AddHours(1), "temp01"),
        };

        var findings = _rule.Evaluate(events, _options).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.Critical, findings[0].Severity);
        Assert.Equal(3, findings[0].Events.Count);
    }

    [Fact]
    public void DoesNotFire_WhenAccountOnlyCreated_NormalProvisioning()
    {
        var events = new[] { TestEvents.Make(EventIds.UserAccountCreated, TestEvents.Base, "newhire01") };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenCreatedAndPromotedButNotDeleted()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.UserAccountCreated, TestEvents.Base, "temp01"),
            TestEvents.Make(EventIds.MemberAddedToSecurityGroup, TestEvents.Base.AddMinutes(5), "temp01"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_WhenDeleteHappensOutsideWindow()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.UserAccountCreated, TestEvents.Base, "temp01"),
            TestEvents.Make(EventIds.MemberAddedToSecurityGroup, TestEvents.Base.AddMinutes(5), "temp01"),
            TestEvents.Make(EventIds.UserAccountDeleted, TestEvents.Base.AddHours(25), "temp01"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }

    [Fact]
    public void DoesNotFire_ForUnrelatedAccountsInterleaved()
    {
        var events = new[]
        {
            TestEvents.Make(EventIds.UserAccountCreated, TestEvents.Base, "temp01"),
            TestEvents.Make(EventIds.MemberAddedToSecurityGroup, TestEvents.Base.AddMinutes(5), "other-account"),
            TestEvents.Make(EventIds.UserAccountDeleted, TestEvents.Base.AddHours(1), "temp01"),
        };

        Assert.Empty(_rule.Evaluate(events, _options));
    }
}
