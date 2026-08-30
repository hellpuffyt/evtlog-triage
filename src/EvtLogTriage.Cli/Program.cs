using EvtLogTriage.Core;
using EvtLogTriage.Core.Models;
using EvtLogTriage.Core.Output;
using EvtLogTriage.Core.Readers;

namespace EvtLogTriage.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var parsed = CliArguments.Parse(args);
            if (parsed.ShowHelp)
            {
                Console.WriteLine(CliArguments.HelpText);
                return 0;
            }

            if (parsed.InputPath is null)
            {
                Console.Error.WriteLine("error: an input file is required. See --help.");
                return 2;
            }

            if (!File.Exists(parsed.InputPath))
            {
                Console.Error.WriteLine($"error: input file not found: {parsed.InputPath}");
                return 2;
            }

            IEventReader reader = parsed.ReaderKind switch
            {
                ReaderKind.Csv => new CsvEventReader(),
                ReaderKind.Json => new JsonEventReader(),
                _ => InferReader(parsed.InputPath),
            };

            using var stream = File.OpenText(parsed.InputPath);
            var events = reader.Read(stream);

            var defaults = TriageOptions.Default;
            var options = new TriageOptions
            {
                Since = parsed.Since,
                MinimumSeverity = parsed.MinimumSeverity,
                IncludeRules = parsed.IncludeRules,
                ExcludeRules = parsed.ExcludeRules,
                ExpectedAdmins = parsed.ExpectedAdmins,
                BusinessHoursStart = parsed.BusinessHoursStart ?? defaults.BusinessHoursStart,
                BusinessHoursEnd = parsed.BusinessHoursEnd ?? defaults.BusinessHoursEnd,
            };

            var engine = new TriageEngine();
            var findings = engine.Run(events, options);

            var output = parsed.Format switch
            {
                OutputFormat.Json => OutputFormatter.ToJson(findings),
                OutputFormat.Timeline => OutputFormatter.ToTimeline(findings),
                _ => OutputFormatter.ToTable(findings),
            };

            Console.WriteLine(output);

            var worstSeverity = findings.Count == 0
                ? Severity.Informational
                : findings.Max(f => f.Severity);

            return worstSeverity >= parsed.FailOnSeverity ? 1 : 0;
        }
        catch (Exception ex) when (ex is InvalidDataException or FormatException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 2;
        }
    }

    private static IEventReader InferReader(string path) =>
        Path.GetExtension(path).Equals(".csv", StringComparison.OrdinalIgnoreCase)
            ? new CsvEventReader()
            : new JsonEventReader();
}
