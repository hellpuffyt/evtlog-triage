using EvtLogTriage.Core.Readers;
using Xunit;

namespace EvtLogTriage.Core.Tests.Readers;

public class JsonEventReaderTests
{
    private readonly JsonEventReader _reader = new();

    [Fact]
    public void Reads_SimpleArrayOfEvents()
    {
        const string json = """
            [
              { "EventId": 4625, "TimeCreated": "2026-03-02T09:00:00Z", "Provider": "Microsoft-Windows-Security-Auditing", "Computer": "HOST1", "Account": "alice", "SourceAddress": "203.0.113.5", "Level": "Information" }
            ]
            """;

        var events = _reader.Read(new StringReader(json));

        Assert.Single(events);
        Assert.Equal(4625, events[0].EventId);
        Assert.Equal("alice", events[0].Account);
        Assert.Equal("203.0.113.5", events[0].SourceAddress);
    }

    [Fact]
    public void Reads_SingleObjectNotArray()
    {
        const string json = """{ "EventId": 1102, "TimeCreated": "2026-03-02T09:00:00Z" }""";

        var events = _reader.Read(new StringReader(json));

        Assert.Single(events);
        Assert.Equal(1102, events[0].EventId);
    }

    [Fact]
    public void Reads_GetWinEventStyleAliasFields()
    {
        const string json = """
            [
              { "Id": 4624, "TimeCreated": "2026-03-02T09:00:00Z", "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": "HOST1", "TargetUserName": "bob", "IpAddress": "198.51.100.9", "LevelDisplayName": "Information" }
            ]
            """;

        var events = _reader.Read(new StringReader(json));

        Assert.Equal(4624, events[0].EventId);
        Assert.Equal("bob", events[0].Account);
        Assert.Equal("198.51.100.9", events[0].SourceAddress);
        Assert.Equal("HOST1", events[0].Computer);
    }

    [Fact]
    public void PreservesUnknownFieldsInData()
    {
        const string json = """
            [
              { "EventId": 7045, "TimeCreated": "2026-03-02T09:00:00Z", "ServiceFileName": "C:\\Windows\\Temp\\x.exe", "ServiceName": "X" }
            ]
            """;

        var events = _reader.Read(new StringReader(json));

        Assert.Equal("C:\\Windows\\Temp\\x.exe", events[0].GetData("ServiceFileName"));
        Assert.Equal("X", events[0].GetData("ServiceName"));
    }

    [Fact]
    public void Throws_WhenEventIdMissing()
    {
        const string json = """[{ "TimeCreated": "2026-03-02T09:00:00Z" }]""";

        Assert.Throws<InvalidDataException>(() => _reader.Read(new StringReader(json)));
    }

    [Fact]
    public void Throws_WhenTimeCreatedMissing()
    {
        const string json = """[{ "EventId": 4624 }]""";

        Assert.Throws<InvalidDataException>(() => _reader.Read(new StringReader(json)));
    }
}
