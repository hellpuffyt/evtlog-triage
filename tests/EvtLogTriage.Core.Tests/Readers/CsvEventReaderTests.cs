using EvtLogTriage.Core.Readers;
using Xunit;

namespace EvtLogTriage.Core.Tests.Readers;

public class CsvEventReaderTests
{
    private readonly CsvEventReader _reader = new();

    [Fact]
    public void Reads_BasicCsvWithHeader()
    {
        const string csv = "EventId,TimeCreated,Provider,Computer,Account,SourceAddress,Level\n" +
            "4625,2026-03-02T09:00:00Z,Microsoft-Windows-Security-Auditing,HOST1,alice,203.0.113.5,Information\n";

        var events = _reader.Read(new StringReader(csv));

        Assert.Single(events);
        Assert.Equal(4625, events[0].EventId);
        Assert.Equal("alice", events[0].Account);
    }

    [Fact]
    public void Reads_MultipleRows()
    {
        const string csv = "EventId,TimeCreated,Account\n" +
            "4624,2026-03-02T09:00:00Z,alice\n" +
            "4625,2026-03-02T09:01:00Z,bob\n";

        var events = _reader.Read(new StringReader(csv));

        Assert.Equal(2, events.Count);
        Assert.Equal("bob", events[1].Account);
    }

    [Fact]
    public void Reads_QuotedFieldsWithEmbeddedCommas()
    {
        const string csv = "EventId,TimeCreated,ServiceFileName\n" +
            "7045,2026-03-02T09:00:00Z,\"C:\\Temp\\a,b.exe\"\n";

        var events = _reader.Read(new StringReader(csv));

        Assert.Equal("C:\\Temp\\a,b.exe", events[0].GetData("ServiceFileName"));
    }

    [Fact]
    public void PreservesExtraColumnsInData()
    {
        const string csv = "EventId,TimeCreated,ServiceFileName,ServiceName\n" +
            "7045,2026-03-02T09:00:00Z,C:\\Windows\\Temp\\x.exe,X\n";

        var events = _reader.Read(new StringReader(csv));

        Assert.Equal("X", events[0].GetData("ServiceName"));
    }

    [Fact]
    public void Throws_WhenEventIdColumnMissing()
    {
        const string csv = "TimeCreated,Account\n2026-03-02T09:00:00Z,alice\n";

        Assert.Throws<InvalidDataException>(() => _reader.Read(new StringReader(csv)));
    }

    [Fact]
    public void ReturnsEmpty_ForHeaderOnlyCsv()
    {
        const string csv = "EventId,TimeCreated,Account\n";

        var events = _reader.Read(new StringReader(csv));

        Assert.Empty(events);
    }
}
