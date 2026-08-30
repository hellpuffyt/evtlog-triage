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
                    result.Format = Enum.Parse<OutputFormat>(RequireValue(args, ref i, arg), ignoreCase: true);
                    break;
                case "--reader":
                    result.ReaderKind = Enum.Parse<ReaderKind>(RequireValue(args, ref i, arg), ignoreCase: true);
                    break;
                case "--since":
                    result.Since = DateTimeOffset.Parse(RequireValue(args, ref i, arg));
                    break;
                case "--severity":
                    result.MinimumSeverity = Enum.Parse<Severity>(RequireValue(args, ref i, arg), ignoreCase: true);
                    break;
                case "--fail-on":
                    result.FailOnSeverity = Enum.Parse<Severity>(RequireValue(args, ref i, arg), ignoreCase: true);
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
                    result.BusinessHoursStart = TimeSpan.Parse(RequireValue(args, ref i, arg));
                    break;
                case "--business-hours-end":
                    result.BusinessHoursEnd = TimeSpan.Parse(RequireValue(args, ref i, arg));
                    break;
                default:
                    if (arg.StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"Unknown option: {arg}");
                    }

                    result.InputPath ??= arg;
                    break;
            }
        }

        return result;
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
