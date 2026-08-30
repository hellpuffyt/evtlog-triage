using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class PrivilegeEscalationRuleTests
{
    private readonly PrivilegeEscalationRule _rule = new();

    [Fact]
    public void Fires_ForUnexpectedAdminAccount()
    {
        var options = new TriageOptions { ExpectedAdmins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "svc-admin" } };
        var events = new[] { TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base, "mallory") };

        var findings = _rule.Evaluate(events, options).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.Medium, findings[0].Severity);
    }

    [Fact]
    public void DoesNotFire_WhenAdminUsingAdminPrivilegesOnExpectedList()
    {
        var options = new TriageOptions { ExpectedAdmins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "svc-admin" } };
        var events = new[] { TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base, "svc-admin") };

        Assert.Empty(_rule.Evaluate(events, options));
    }

    [Fact]
    public void ExpectedAdminMatch_IsCaseInsensitive()
    {
        var options = new TriageOptions { ExpectedAdmins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "SVC-Admin" } };
        var events = new[] { TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base, "svc-admin") };

        Assert.Empty(_rule.Evaluate(events, options));
    }

    [Fact]
    public void IgnoresUnrelatedEvents()
    {
        var options = TriageOptions.Default;
        var events = new[] { TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base, "mallory") };

        Assert.Empty(_rule.Evaluate(events, options));
    }

    [Fact]
    public void Fires_ForEachUnexpectedAccountSeparately()
    {
        var options = TriageOptions.Default;
        var events = new[]
        {
            TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base, "mallory"),
            TestEvents.Make(EventIds.SpecialPrivilegesAssigned, TestEvents.Base.AddMinutes(1), "eve"),
        };

        var findings = _rule.Evaluate(events, options).ToList();

        Assert.Equal(2, findings.Count);
    }
}
