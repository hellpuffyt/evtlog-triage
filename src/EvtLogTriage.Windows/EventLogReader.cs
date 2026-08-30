using System.Collections.Generic;
using System.Runtime.Versioning;
using WinEventLogReader = System.Diagnostics.Eventing.Reader.EventLogReader;
using WinEventLogQuery = System.Diagnostics.Eventing.Reader.EventLogQuery;
using WinEventRecord = System.Diagnostics.Eventing.Reader.EventRecord;
using WinPathType = System.Diagnostics.Eventing.Reader.PathType;
using WinEventLogException = System.Diagnostics.Eventing.Reader.EventLogException;

namespace EvtLogTriage.Windows;

/// <summary>
/// Reads events directly from a live Windows Event Log channel or a local .evtx file using
/// <see cref="System.Diagnostics.Eventing.Reader"/>. Windows-only: this API has no Linux/macOS
/// implementation, which is why all detection logic lives in the platform-neutral core library
/// and only this reader (plus the JSON/CSV readers) are platform-specific.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsEventReader
{
    /// <summary>Reads events from a live channel, e.g. "Security".</summary>
    public static IReadOnlyList<Core.Models.EventRecord> ReadChannel(string channelName, string? xpathQuery = null)
    {
        var query = new WinEventLogQuery(channelName, WinPathType.LogName, xpathQuery ?? "*");
        using var reader = new WinEventLogReader(query);
        return ReadAll(reader);
    }

    /// <summary>Reads events from an exported .evtx file.</summary>
    public static IReadOnlyList<Core.Models.EventRecord> ReadEvtxFile(string filePath)
    {
        var query = new WinEventLogQuery(filePath, WinPathType.FilePath);
        using var reader = new WinEventLogReader(query);
        return ReadAll(reader);
    }

    private static List<Core.Models.EventRecord> ReadAll(WinEventLogReader reader)
    {
        var results = new List<Core.Models.EventRecord>();
        while (reader.ReadEvent() is { } evt)
        {
            using (evt)
            {
                results.Add(Convert(evt));
            }
        }

        return results;
    }

    private static Core.Models.EventRecord Convert(WinEventRecord evt)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? account = null;
        string? sourceAddress = null;

        try
        {
            var properties = evt.Properties;
            for (var i = 0; i < properties.Count; i++)
            {
                var value = properties[i].Value?.ToString() ?? string.Empty;
                data[$"Data{i}"] = value;
            }

            // Heuristic: for logon-family events, EventData commonly carries TargetUserName and
            // IpAddress at well-known indices in the standard security auditing templates.
            account = evt.Properties.Count > 5 ? evt.Properties[5].Value?.ToString() : null;
            sourceAddress = evt.Properties.Count > 18 ? evt.Properties[18].Value?.ToString() : null;
        }
        catch (WinEventLogException)
        {
            // Some providers/records don't expose properties the same way; fall back to what we have.
        }

        return new Core.Models.EventRecord
        {
            EventId = evt.Id,
            TimeCreated = evt.TimeCreated.HasValue
                ? new DateTimeOffset(evt.TimeCreated.Value)
                : DateTimeOffset.UtcNow,
            Provider = evt.ProviderName ?? string.Empty,
            Computer = evt.MachineName ?? string.Empty,
            Account = account,
            SourceAddress = sourceAddress,
            Level = evt.LevelDisplayName ?? "Information",
            Data = data,
        };
    }
}
