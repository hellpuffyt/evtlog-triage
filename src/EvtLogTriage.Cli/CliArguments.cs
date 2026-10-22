using System.Globalization;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Cli;

public enum OutputFormat
{
    Table,
    Json,
    Timeline,
}

public enum ReaderKind
{
    Auto,
    Json,
    Csv,
}

/// <summary>Parsed command-line arguments for the CLI.</summary>
public sealed class CliArguments
{
    public string? InputPath { get; private set; }
    public OutputFormat Format { get; private set; } = OutputFormat.Table;
    public ReaderKind ReaderKind { get; private set; } = ReaderKind.Auto;
    public DateTimeOffset? Since { get; private set; }
    public Severity MinimumSeverity { get; private set; } = Severity.Informational;
    public Severity FailOnSeverity { get; private set; } = Severity.High;
    public HashSet<string>? IncludeRules { get; private set; }
    public HashSet<string> ExcludeRules { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ExpectedAdmins { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public TimeSpan? BusinessHoursStart { get; private set; }
    public TimeSpan? BusinessHoursEnd { get; private set; }
    public bool ShowHelp { get; private set; }

    public const string HelpText = """
        evtlog-triage - correlate Windows Event Log sequences into security findings

        Usage:
          evtlog-triage <input-file> [options]

        Options:
          --format <table|json|timeline>   Output format (default: table)
          --reader <json|csv>               Force a reader instead of inferring from extension
          --since <ISO-8601 datetime>       Only consider events at or after this time
          --severity <level>                Minimum severity to report (default: Informational)
          --fail-on <level>                 Exit non-zero if any finding is at/above this severity (default: High)
          --rules <RULE1,RULE2,...>         Only run these rule IDs
          --exclude <RULE1,RULE2,...>       Skip these rule IDs
          --expected-admins <a,b,...>       Accounts allowed to hold admin privileges (default: none)
          --business-hours-start <HH:mm>    Business hours start (default: 08:00)
          --business-hours-end <HH:mm>      Business hours end (default: 18:00)
          --help                            Show this help text

        Severity levels: Informational, Low, Medium, High, Critical
        """;

    public static CliArguments Parse(string[] args)
    {
        var result = new CliArguments();

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "--help" or "-h":
                    result.ShowHelp = true;
                    return result;
                case "--format":
                    result.Format = ParseEnum<OutputFormat>(RequireValue(args, ref i, arg), arg);
                    break;
                case "--reader":
                    result.ReaderKind = ParseEnum<ReaderKind>(RequireValue(args, ref i, arg), arg);
                    break;
                case "--since":
                    result.Since = ParseSince(RequireValue(args, ref i, arg));
                    break;
                case "--severity":
                    result.MinimumSeverity = ParseEnum<Severity>(RequireValue(args, ref i, arg), arg);
                    break;
                case "--fail-on":
                    result.FailOnSeverity = ParseEnum<Severity>(RequireValue(args, ref i, arg), arg);
                    break;
                case "--rules":
                    result.IncludeRules = RequireValue(args, ref i, arg)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    break;
                case "--exclude":
                    result.ExcludeRules = RequireValue(args, ref i, arg)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    break;
                case "--expected-admins":
                    result.ExpectedAdmins = RequireValue(args, ref i, arg)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    break;
                case "--business-hours-start":
                    result.BusinessHoursStart = ParseTimeOfDay(RequireValue(args, ref i, arg), arg);
                    break;
                case "--business-hours-end":
                    result.BusinessHoursEnd = ParseTimeOfDay(RequireValue(args, ref i, arg), arg);
                    break;
                default:
                    if (arg.StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"Unknown option: {arg}");
                    }

                    if (result.InputPath is not null)
                    {
                        throw new ArgumentException(
                            $"Only one input file is supported (got '{result.InputPath}' and '{arg}').");
                    }

                    result.InputPath = arg;
                    break;
            }
        }

        var start = result.BusinessHoursStart ?? TimeSpan.FromHours(8);
        var end = result.BusinessHoursEnd ?? TimeSpan.FromHours(18);
        if (start >= end)
        {
            throw new ArgumentException(
                $"--business-hours-start ({start:hh\\:mm}) must be earlier than --business-hours-end ({end:hh\\:mm}).");
        }

        return result;
    }

    // Enum.Parse alone also accepts any integer ("--severity 42") and throws an exception the CLI
    // did not handle for unknown names; accept only the documented names.
    private static T ParseEnum<T>(string value, string optionName)
        where T : struct, Enum
    {
        if (!int.TryParse(value, out _) && Enum.TryParse<T>(value, ignoreCase: true, out var parsed) &&
            Enum.IsDefined(parsed))
        {
            return parsed;
        }

        throw new ArgumentException(
            $"Invalid value '{value}' for {optionName}. Expected one of: {string.Join(", ", Enum.GetNames<T>())}.");
    }

    // Timestamps without an explicit offset are read as UTC, matching how the JSON and CSV readers
    // interpret event timestamps, and parsing does not depend on the machine's culture.
    private static DateTimeOffset ParseSince(string value)
    {
        if (DateTimeOffset.TryParse(
                value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            return parsed;
        }

        throw new ArgumentException($"Invalid --since value '{value}'. Expected an ISO-8601 date/time.");
    }

    // TimeSpan.Parse would read "9" as nine *days* and throw OverflowException for "25:99".
    private static readonly string[] TimeOfDayFormats = { @"h\:mm", @"hh\:mm" };

    private static TimeSpan ParseTimeOfDay(string value, string optionName)
    {
        if (TimeSpan.TryParseExact(value, TimeOfDayFormats, CultureInfo.InvariantCulture, out var parsed) &&
            parsed >= TimeSpan.Zero && parsed < TimeSpan.FromDays(1))
        {
            return parsed;
        }

        throw new ArgumentException($"Invalid {optionName} value '{value}'. Expected HH:mm between 00:00 and 23:59.");
    }

    private static string RequireValue(string[] args, ref int index, string optionName)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Option {optionName} requires a value.");
        }

        index++;
        return args[index];
    }
}
