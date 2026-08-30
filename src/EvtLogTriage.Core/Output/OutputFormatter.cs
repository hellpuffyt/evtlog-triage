using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Output;

/// <summary>Renders findings as a human-readable table, JSON, or a chronological timeline.</summary>
public static class OutputFormatter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    public static string ToTable(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return "No findings.";
        }

        var rows = findings.Select(f => new[]
        {
            f.RuleId,
            f.Severity.ToString(),
            f.WindowStart.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            f.WindowEnd.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            f.Summary,
        }).ToList();

        string[] headers = { "RULE", "SEVERITY", "WINDOW START", "WINDOW END", "SUMMARY" };
        var widths = headers.Select((h, i) => Math.Max(h.Length, rows.Count == 0 ? 0 : rows.Max(r => r[i].Length))).ToArray();

        var sb = new StringBuilder();
        AppendRow(sb, headers, widths);
        sb.AppendLine(string.Join("  ", widths.Select(w => new string('-', w))));
        foreach (var row in rows)
        {
            AppendRow(sb, row, widths);
        }

        return sb.ToString().TrimEnd('\n', '\r');
    }

    private static void AppendRow(StringBuilder sb, IReadOnlyList<string> cells, int[] widths)
    {
        sb.AppendLine(string.Join("  ", cells.Select((c, i) => c.PadRight(widths[i]))));
    }

    public static string ToJson(IReadOnlyList<Finding> findings)
    {
        var payload = findings.Select(f => new
        {
            f.RuleId,
            f.RuleName,
            Severity = f.Severity.ToString(),
            WindowStart = f.WindowStart,
            WindowEnd = f.WindowEnd,
            f.Summary,
            f.Explanation,
            f.Recommendation,
            EventIds = f.EventIds,
            Events = f.Events.Select(e => new
            {
                e.EventId,
                e.TimeCreated,
                e.Provider,
                e.Computer,
                e.Account,
                e.SourceAddress,
                e.Level,
            }),
        });

        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    public static string ToTimeline(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return "No findings.";
        }

        var sb = new StringBuilder();
        foreach (var finding in findings.OrderBy(f => f.WindowStart))
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"[{finding.WindowStart:yyyy-MM-dd HH:mm:ss}] {finding.Severity,-13} {finding.RuleId}: {finding.Summary}");
            foreach (var evt in finding.Events)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"    {evt.TimeCreated:HH:mm:ss}  EventID={evt.EventId,-6} Account={evt.Account ?? "-",-20} Source={evt.SourceAddress ?? "-"}");
            }
        }

        return sb.ToString().TrimEnd('\n', '\r');
    }
}
