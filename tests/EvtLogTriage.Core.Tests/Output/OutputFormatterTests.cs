using System.Text.Json;
using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Output;
using Xunit;

namespace EvtLogTriage.Core.Tests.Output;

public class OutputFormatterTests
{
    private static Finding SampleFinding() => new()
    {
        RuleId = "LOG-TAMPERING",
        RuleName = "Audit log cleared",
        Severity = Severity.Critical,
        WindowStart = TestEvents.Base,
        WindowEnd = TestEvents.Base,
        Events = new[] { TestEvents.Make(EventIds.AuditLogCleared, TestEvents.Base, "administrator") },
        Summary = "Security audit log cleared",
        Explanation = "explanation text",
        Recommendation = "recommendation text",
    };

    [Fact]
    public void ToTable_ReturnsNoFindingsMessage_WhenEmpty()
    {
        Assert.Equal("No findings.", OutputFormatter.ToTable(Array.Empty<Finding>()));
    }

    [Fact]
    public void ToTable_IncludesRuleIdAndSeverity()
    {
        var table = OutputFormatter.ToTable(new[] { SampleFinding() });

        Assert.Contains("LOG-TAMPERING", table);
        Assert.Contains("Critical", table);
    }

    [Fact]
    public void ToJson_IsValidJsonContainingRuleId()
    {
        var json = OutputFormatter.ToJson(new[] { SampleFinding() });

        using var doc = JsonDocument.Parse(json);
        Assert.Equal("LOG-TAMPERING", doc.RootElement[0].GetProperty("RuleId").GetString());
    }

    [Fact]
    public void ToTimeline_ReturnsNoFindingsMessage_WhenEmpty()
    {
        Assert.Equal("No findings.", OutputFormatter.ToTimeline(Array.Empty<Finding>()));
    }

    [Fact]
    public void ToTimeline_IncludesEventIdOfCorrelatedEvents()
    {
        var timeline = OutputFormatter.ToTimeline(new[] { SampleFinding() });

        Assert.Contains("EventID=1102", timeline);
    }
}
