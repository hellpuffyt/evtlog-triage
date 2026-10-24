using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Readers;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests.Readers;

/// <summary>
/// Synthetic events in the Windows event XML schema. The field names follow Microsoft's
/// documented security-auditing templates; these fixtures were written by hand, not captured
/// from a Windows host.
/// </summary>
public class EventXmlParserTests
{
    private static string Event(int id, string time, string eventData, string level = "0", string? userData = null) =>
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
        "<System><Provider Name='Microsoft-Windows-Security-Auditing' />" +
        $"<EventID>{id}</EventID><Level>{level}</Level>" +
        $"<TimeCreated SystemTime='{time}' /><Computer>HOST1.example.test</Computer></System>" +
        (eventData.Length > 0 ? $"<EventData>{eventData}</EventData>" : string.Empty) +
        (userData is null ? string.Empty : $"<UserData>{userData}</UserData>") +
        "</Event>";

    private static string Data(string name, string value) => $"<Data Name='{name}'>{value}</Data>";

    private static string FailedLogon(string time, string user, string ip) => Event(4625, time,
        Data("SubjectUserSid", "S-1-0-0") + Data("SubjectUserName", "-") + Data("TargetUserSid", "S-1-0-0") +
        Data("TargetUserName", user) + Data("TargetDomainName", "EXAMPLE") + Data("Status", "0xc000006d") +
        Data("LogonType", "3") + Data("ProcessName", "-") + Data("IpAddress", ip) + Data("IpPort", "51234"));

    [Fact]
    public void FailedLogon_TakesTargetUserAndIpAddressByName()
    {
        var evt = EventXmlParser.Parse(FailedLogon("2026-03-02T09:00:00.1234567Z", "alice", "203.0.113.7"));

        Assert.Equal(4625, evt.EventId);
        Assert.Equal(new DateTimeOffset(2026, 3, 2, 9, 0, 0, 123, TimeSpan.Zero).AddTicks(4567), evt.TimeCreated);
        Assert.Equal("alice", evt.Account);
        Assert.Equal("203.0.113.7", evt.SourceAddress);
        Assert.Equal("HOST1.example.test", evt.Computer);
        Assert.Equal("Microsoft-Windows-Security-Auditing", evt.Provider);
        Assert.Equal("0xc000006d", evt.GetData("Status"));
    }

    [Fact]
    public void LocalFailedLogon_DashAddressBecomesNull()
    {
        var evt = EventXmlParser.Parse(FailedLogon("2026-03-02T09:00:00Z", "alice", "-"));
        Assert.Null(evt.SourceAddress);
    }

    [Fact]
    public void SpecialPrivileges_UsesSubjectUserName()
    {
        var evt = EventXmlParser.Parse(Event(4672, "2026-03-02T09:00:00Z",
            Data("SubjectUserSid", "S-1-5-21-1") + Data("SubjectUserName", "bob") +
            Data("SubjectDomainName", "EXAMPLE") + Data("SubjectLogonId", "0x3e7") +
            Data("PrivilegeList", "SeDebugPrivilege")));
        Assert.Equal("bob", evt.Account);
    }

    [Fact]
    public void ServiceInstall_ExposesImagePathToTheRule()
    {
        var evt = EventXmlParser.Parse(Event(7045, "2026-03-02T09:00:00Z",
            Data("ServiceName", "updater") + Data("ImagePath", "C:\\Users\\Public\\upd.exe") +
            Data("ServiceType", "user mode service") + Data("StartType", "auto start") + Data("AccountName", "LocalSystem")));

        var findings = new ServiceInstallRule().Evaluate(new[] { evt }, TriageOptions.Default).ToList();
        Assert.Single(findings);
    }

    [Fact]
    public void AuditLogCleared_ReadsSubjectFromUserData()
    {
        var evt = EventXmlParser.Parse(Event(1102, "2026-03-02T09:00:00Z", string.Empty, "4",
            "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>" +
            "<SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>mallory</SubjectUserName></LogFileCleared>"));
        Assert.Equal("mallory", evt.Account);
    }

    [Fact]
    public void MemberAddedToGroup_UsesMemberNameThenMemberSid()
    {
        var named = EventXmlParser.Parse(Event(4732, "2026-03-02T09:00:00Z",
            Data("MemberName", "CN=temp,OU=x") + Data("MemberSid", "S-1-5-21-9") + Data("TargetUserName", "Administrators")));
        Assert.Equal("CN=temp,OU=x", named.Account);

        var local = EventXmlParser.Parse(Event(4732, "2026-03-02T09:00:00Z",
            Data("MemberName", "-") + Data("MemberSid", "S-1-5-21-9") + Data("TargetUserName", "Administrators")));
        Assert.Equal("S-1-5-21-9", local.Account);
    }

    [Fact]
    public void BruteForceFiresOnParsedXmlEvents()
    {
        var events = Enumerable.Range(0, 10)
            .Select(i => EventXmlParser.Parse(FailedLogon($"2026-03-02T09:00:{i:00}Z", "alice", "203.0.113.7")))
            .ToList();
        var findings = new BruteForceRule().Evaluate(events, TriageOptions.Default).ToList();
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<Event>")]
    [InlineData("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>x</EventID></System></Event>")]
    [InlineData("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID></System></Event>")]
    [InlineData("<!DOCTYPE e [<!ENTITY x SYSTEM 'file:///etc/hostname'>]><Event>&x;</Event>")]
    public void MalformedOrHostileXml_ThrowsInvalidDataException(string xml)
    {
        Assert.Throws<InvalidDataException>(() => EventXmlParser.Parse(xml));
    }
}
