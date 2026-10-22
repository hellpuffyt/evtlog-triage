using EvtLogTriage.Cli;
using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Readers;
using EvtLogTriage.Core.Rules;
using Xunit;

namespace EvtLogTriage.Core.Tests;

/// <summary>Regression tests for defects found during the production-readiness audit.</summary>
public class HardeningRegressionTests
{
    // --- correlation ---------------------------------------------------------------------------

    [Fact]
    public void BruteForce_FortyFailuresInTwoMinutes_IsOneFindingWithAllForty()
    {
        var events = Enumerable.Range(0, 40)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i * 3), "alice", "203.0.113.5"))
            .ToList();
        var options = new TriageOptions { BruteForceThreshold = 10, BruteForceWindow = TimeSpan.FromMinutes(5) };

        var findings = new BruteForceRule().Evaluate(events, options).ToList();

        var finding = Assert.Single(findings);
        Assert.Equal(40, finding.Events.Count);
        Assert.StartsWith("40 failed logons", finding.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void BruteForce_BurstsInSeparateWindows_StaySeparate()
    {
        var first = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddSeconds(i), "alice", "203.0.113.5"));
        var second = Enumerable.Range(0, 10)
            .Select(i => TestEvents.Make(EventIds.FailedLogon, TestEvents.Base.AddMinutes(30).AddSeconds(i), "alice", "203.0.113.5"));
        var options = new TriageOptions { BruteForceThreshold = 10, BruteForceWindow = TimeSpan.FromMinutes(5) };

        var findings = new BruteForceRule().Evaluate(first.Concat(second).ToList(), options).ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(10, f.Events.Count));
    }

    [Fact]
    public void BruteForce_DashPlaceholderAddressesFromDifferentAccountsAreNotMerged()
    {
        // Local 4625s carry IpAddress "-". Five accounts failing twice each is not one brute-force
        // source; before normalization they were all grouped under the "-" key and fired.
        const string csvHeader = "EventId,TimeCreated,Account,SourceAddress\n";
        var rows = Enumerable.Range(0, 10)
            .Select(i => $"4625,2026-03-02T09:00:{i:00}Z,user{i % 5},-\n");
        var events = new CsvEventReader().Read(new StringReader(csvHeader + string.Concat(rows)));

        Assert.All(events, e => Assert.Null(e.SourceAddress));
        var options = new TriageOptions { BruteForceThreshold = 10, BruteForceWindow = TimeSpan.FromMinutes(5) };
        Assert.Empty(new BruteForceRule().Evaluate(events, options));
    }

    // --- readers -------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("[{\"EventId\":4625,")]
    [InlineData("not json")]
    [InlineData("[1,2,3]")]
    [InlineData("42")]
    [InlineData("[{\"EventId\":1e40,\"TimeCreated\":\"2026-01-01T00:00:00Z\"}]")]
    [InlineData("[{\"EventId\":4625.5,\"TimeCreated\":\"2026-01-01T00:00:00Z\"}]")]
    [InlineData("[{\"EventId\":4625,\"TimeCreated\":\"/Date(123\"}]")]
    [InlineData("[{\"EventId\":4625,\"TimeCreated\":\"/Date(99999999999999999999)/\"}]")]
    public void JsonReader_MalformedInput_ThrowsInvalidDataException(string json)
    {
        Assert.Throws<InvalidDataException>(() => new JsonEventReader().Read(new StringReader(json)));
    }

    [Fact]
    public void JsonReader_DateWithOffsetSuffix_IsParsed()
    {
        const string json = "[{\"EventId\":4625,\"TimeCreated\":\"/Date(1767225600000+0100)/\"}]";
        var events = new JsonEventReader().Read(new StringReader(json));
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1767225600000), events[0].TimeCreated);
    }

    [Fact]
    public void JsonReader_NormalizesDashAndBlankIdentities()
    {
        const string json = "[{\"EventId\":4625,\"TimeCreated\":\"2026-01-01T00:00:00Z\",\"Account\":\" \",\"IpAddress\":\"-\"}]";
        var evt = Assert.Single(new JsonEventReader().Read(new StringReader(json)));
        Assert.Null(evt.Account);
        Assert.Null(evt.SourceAddress);
    }

    [Fact]
    public void CsvReader_SkipsWindowsPowerShellTypeLine()
    {
        const string csv = "#TYPE Selected.System.Diagnostics.Eventing.Reader.EventLogRecord\n" +
            "\"EventId\",\"TimeCreated\",\"Account\"\n" +
            "\"4625\",\"2026-01-05T02:10:00Z\",\"alice\"\n";
        var evt = Assert.Single(new CsvEventReader().Read(new StringReader(csv)));
        Assert.Equal(4625, evt.EventId);
        Assert.Equal("alice", evt.Account);
    }

    // --- CLI -----------------------------------------------------------------------------------

    [Theory]
    [InlineData("--severity", "42")]
    [InlineData("--severity", "Loud")]
    [InlineData("--fail-on", "7")]
    [InlineData("--format", "xml")]
    [InlineData("--reader", "evtx")]
    [InlineData("--business-hours-start", "9")]
    [InlineData("--business-hours-start", "25:99")]
    [InlineData("--business-hours-end", "24:00")]
    [InlineData("--since", "notadate")]
    public void CliArguments_RejectsInvalidValues(string option, string value)
    {
        Assert.Throws<ArgumentException>(() => CliArguments.Parse(new[] { "events.json", option, value }));
    }

    [Fact]
    public void CliArguments_RejectsBusinessHoursThatEndBeforeTheyStart()
    {
        Assert.Throws<ArgumentException>(() => CliArguments.Parse(
            new[] { "events.json", "--business-hours-start", "18:00", "--business-hours-end", "08:00" }));
    }

    [Fact]
    public void CliArguments_RejectsASecondInputFile()
    {
        Assert.Throws<ArgumentException>(() => CliArguments.Parse(new[] { "a.json", "b.json" }));
    }

    [Fact]
    public void CliArguments_SinceWithoutOffsetIsUtc()
    {
        var parsed = CliArguments.Parse(new[] { "events.json", "--since", "2026-01-05T02:00:00" });
        Assert.Equal(new DateTimeOffset(2026, 1, 5, 2, 0, 0, TimeSpan.Zero), parsed.Since);
    }

    [Theory]
    [InlineData("[{\"EventId\":4625,")]
    [InlineData("")]
    [InlineData("[1]")]
    public void Program_MalformedInputExitsTwoInsteadOfCrashing(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"evtlog-triage-test-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, content);
        try
        {
            Assert.Equal(2, Program.Main(new[] { path }));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Program_UnknownOptionExitsTwoInsteadOfCrashing()
    {
        Assert.Equal(2, Program.Main(new[] { "events.json", "--bogus" }));
    }
}
