using System.Collections.Generic;
using System.Globalization;
using System.IO;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Readers;

/// <summary>
/// Reads events exported as CSV with a header row, e.g. via
/// <c>Get-WinEvent ... | Select-Object ... | Export-Csv</c>. Expected/recognized column names
/// (case-insensitive): EventId, TimeCreated, Provider, Computer, Account, SourceAddress, Level.
/// Any other column is preserved in <see cref="EventRecord.Data"/>. Supports RFC 4180 style
/// quoting (double-quoted fields, embedded commas, "" for an escaped quote).
/// </summary>
public sealed class CsvEventReader : IEventReader
{
    private static readonly HashSet<string> KnownColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "EventId", "TimeCreated", "Provider", "Computer", "Account", "SourceAddress", "Level",
    };

    public IReadOnlyList<EventRecord> Read(TextReader input)
    {
        var rows = ParseCsv(input);
        if (rows.Count == 0)
        {
            return Array.Empty<EventRecord>();
        }

        var header = rows[0];
        var results = new List<EventRecord>(rows.Count - 1);

        for (var r = 1; r < rows.Count; r++)
        {
            var row = rows[r];
            var byColumn = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var c = 0; c < header.Count && c < row.Count; c++)
            {
                byColumn[header[c]] = row[c];
            }

            if (!byColumn.TryGetValue("EventId", out var eventIdRaw) || !int.TryParse(eventIdRaw, out var eventId))
            {
                throw new InvalidDataException($"CSV row {r + 1} is missing a valid EventId column.");
            }

            if (!byColumn.TryGetValue("TimeCreated", out var timeRaw) ||
                !DateTimeOffset.TryParse(
                    timeRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time))
            {
                throw new InvalidDataException($"CSV row {r + 1} is missing a valid TimeCreated column.");
            }

            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (key, value) in byColumn)
            {
                if (!KnownColumns.Contains(key))
                {
                    data[key] = value;
                }
            }

            results.Add(new EventRecord
            {
                EventId = eventId,
                TimeCreated = time,
                Provider = byColumn.GetValueOrDefault("Provider", string.Empty),
                Computer = byColumn.GetValueOrDefault("Computer", string.Empty),
                Account = byColumn.GetValueOrDefault("Account"),
                SourceAddress = byColumn.GetValueOrDefault("SourceAddress"),
                Level = byColumn.GetValueOrDefault("Level", "Information"),
                Data = data,
            });
        }

        return results;
    }

    private static List<List<string>> ParseCsv(TextReader input)
    {
        var rows = new List<List<string>>();
        var field = new System.Text.StringBuilder();
        var row = new List<string>();
        var inQuotes = false;
        var sawAnyChar = false;

        int ci;
        while ((ci = input.Read()) != -1)
        {
            var c = (char)ci;
            sawAnyChar = true;

            if (inQuotes)
            {
                if (c == '"')
                {
                    if (input.Peek() == '"')
                    {
                        input.Read();
                        field.Append('"');
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    field.Append(c);
                }

                continue;
            }

            switch (c)
            {
                case '"':
                    inQuotes = true;
                    break;
                case ',':
                    row.Add(field.ToString());
                    field.Clear();
                    break;
                case '\r':
                    break;
                case '\n':
                    row.Add(field.ToString());
                    field.Clear();
                    if (row.Count > 1 || !string.IsNullOrEmpty(row[0]))
                    {
                        rows.Add(row);
                    }

                    row = new List<string>();
                    break;
                default:
                    field.Append(c);
                    break;
            }
        }

        if (sawAnyChar && (field.Length > 0 || row.Count > 0))
        {
            row.Add(field.ToString());
            if (row.Count > 1 || !string.IsNullOrEmpty(row[0]))
            {
                rows.Add(row);
            }
        }

        return rows;
    }
}
