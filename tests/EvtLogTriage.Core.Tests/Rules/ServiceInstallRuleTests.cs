using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Rules;

public class ServiceInstallRuleTests
{
    private readonly ServiceInstallRule _rule = new();

    private static EventRecord ServiceEvent(string path, string name = "SuspiciousSvc") => TestEvents.Make(
        EventIds.ServiceInstalled,
        TestEvents.Base,
        data: new Dictionary<string, string>
        {
            ["ServiceFileName"] = path,
            ["ServiceName"] = name,
        });

    [Theory]
    [InlineData(@"C:\Users\alice\AppData\Local\Temp\svc.exe")]
    [InlineData(@"C:\Windows\Temp\payload.exe")]
    [InlineData(@"C:\Users\Public\backdoor.exe")]
    [InlineData(@"C:\ProgramData\updater.exe")]
    [InlineData(@"C:\Users\alice\Downloads\tool.exe")]
    public void Fires_ForSuspiciousPaths(string path)
    {
        var findings = _rule.Evaluate(new[] { ServiceEvent(path) }, TriageOptions.Default).ToList();

        Assert.Single(findings);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Vendor\App\service.exe")]
    [InlineData(@"C:\Windows\System32\svchost.exe")]
    [InlineData(@"C:\Program Files (x86)\Vendor\agent.exe")]
    public void DoesNotFire_ForNormalInstallPaths(string path)
    {
        var findings = _rule.Evaluate(new[] { ServiceEvent(path) }, TriageOptions.Default).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void DoesNotFire_WhenNoPathDataPresent()
    {
        var evt = TestEvents.Make(EventIds.ServiceInstalled, TestEvents.Base);

        Assert.Empty(_rule.Evaluate(new[] { evt }, TriageOptions.Default));
    }

    [Fact]
    public void DoesNotFire_ForUnrelatedEvents()
    {
        var evt = TestEvents.Make(EventIds.SuccessfulLogon, TestEvents.Base);

        Assert.Empty(_rule.Evaluate(new[] { evt }, TriageOptions.Default));
    }

    [Fact]
    public void PathMatch_IsCaseInsensitive()
    {
        var evt = ServiceEvent(@"C:\WINDOWS\TEMP\payload.exe");

        Assert.Single(_rule.Evaluate(new[] { evt }, TriageOptions.Default));
    }

    [Fact]
    public void SummaryIncludesServiceName()
    {
        var evt = ServiceEvent(@"C:\Windows\Temp\payload.exe", "EvilSvc");

        var findings = _rule.Evaluate(new[] { evt }, TriageOptions.Default).ToList();

        Assert.Contains("EvilSvc", findings[0].Summary);
    }
}
