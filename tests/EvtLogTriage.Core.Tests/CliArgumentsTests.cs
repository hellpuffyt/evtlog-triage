using EvtLogTriage.Cli;
using EvtLogTriage.Core.Models;
using Xunit;

namespace EvtLogTriage.Core.Tests;

public class CliArgumentsTests
{
    [Fact]
    public void Parse_ReadsInputPathAsPositionalArgument()
    {
        var parsed = CliArguments.Parse(new[] { "events.json" });

        Assert.Equal("events.json", parsed.InputPath);
        Assert.Equal(OutputFormat.Table, parsed.Format);
    }

    [Fact]
    public void Parse_ReadsFormatOption()
    {
        var parsed = CliArguments.Parse(new[] { "events.json", "--format", "json" });

        Assert.Equal(OutputFormat.Json, parsed.Format);
    }

    [Fact]
    public void Parse_ReadsSeverityAndFailOn()
    {
        var parsed = CliArguments.Parse(new[] { "events.json", "--severity", "Medium", "--fail-on", "Critical" });

        Assert.Equal(Severity.Medium, parsed.MinimumSeverity);
        Assert.Equal(Severity.Critical, parsed.FailOnSeverity);
    }

    [Fact]
    public void Parse_ReadsRulesAndExcludeAsCommaSeparated()
    {
        var parsed = CliArguments.Parse(new[] { "events.json", "--rules", "BRUTE-FORCE,LOG-TAMPERING", "--exclude", "OFF-HOURS-LOGON" });

        Assert.NotNull(parsed.IncludeRules);
        Assert.Contains("BRUTE-FORCE", parsed.IncludeRules!);
        Assert.Contains("LOG-TAMPERING", parsed.IncludeRules!);
        Assert.Contains("OFF-HOURS-LOGON", parsed.ExcludeRules);
    }

    [Fact]
    public void Parse_SetsShowHelp_ForHelpFlag()
    {
        var parsed = CliArguments.Parse(new[] { "--help" });

        Assert.True(parsed.ShowHelp);
    }

    [Fact]
    public void Parse_ThrowsForUnknownOption()
    {
        Assert.Throws<ArgumentException>(() => CliArguments.Parse(new[] { "events.json", "--bogus" }));
    }

    [Fact]
    public void Parse_DefaultsFailOnToHigh()
    {
        var parsed = CliArguments.Parse(new[] { "events.json" });

        Assert.Equal(Severity.High, parsed.FailOnSeverity);
    }

    [Fact]
    public void Parse_ReadsExpectedAdmins()
    {
        var parsed = CliArguments.Parse(new[] { "events.json", "--expected-admins", "svc-admin,root-ops" });

        Assert.Contains("svc-admin", parsed.ExpectedAdmins);
        Assert.Contains("root-ops", parsed.ExpectedAdmins);
    }

    [Fact]
    public void Parse_ReadsBusinessHours()
    {
        var parsed = CliArguments.Parse(new[] { "events.json", "--business-hours-start", "07:00", "--business-hours-end", "19:00" });

        Assert.Equal(TimeSpan.FromHours(7), parsed.BusinessHoursStart);
        Assert.Equal(TimeSpan.FromHours(19), parsed.BusinessHoursEnd);
    }
}
