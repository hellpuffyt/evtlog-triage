using System.Collections.Generic;
using System.Runtime.Versioning;
using WinEventLogReader = System.Diagnostics.Eventing.Reader.EventLogReader;
using WinEventLogQuery = System.Diagnostics.Eventing.Reader.EventLogQuery;
using WinEventRecord = System.Diagnostics.Eventing.Reader.EventRecord;
using WinPathType = System.Diagnostics.Eventing.Reader.PathType;

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

    // The record's XML rendering names every EventData field, so the shared, platform-neutral
    // EventXmlParser can pick the account and source address by name for each event ID. (A fixed
    // positional mapping is wrong for most of the supported events: e.g. index 18 of a 4625 is
    // ProcessName, not IpAddress.)
    private static Core.Models.EventRecord Convert(WinEventRecord evt) =>
        Core.Readers.EventXmlParser.Parse(evt.ToXml());
}
