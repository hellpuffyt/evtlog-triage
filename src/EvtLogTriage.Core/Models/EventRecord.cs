using System.Collections.Generic;

namespace EvtLogTriage.Core.Models;

/// <summary>
/// A platform-neutral representation of a single Windows Event Log entry.
/// This is the shape every reader (EVTX, JSON export, CSV export) normalizes into,
/// and the only shape the detection rules ever see.
/// </summary>
public sealed class EventRecord
{
    /// <summary>The numeric Windows Event ID (e.g. 4624, 4625, 4672).</summary>
    public required int EventId { get; init; }

    /// <summary>UTC or offset-aware timestamp the event was created.</summary>
    public required DateTimeOffset TimeCreated { get; init; }

    /// <summary>Provider/source name, e.g. "Microsoft-Windows-Security-Auditing".</summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>Computer the event was logged on.</summary>
    public string Computer { get; init; } = string.Empty;

    /// <summary>The account name relevant to the event (target account for logons, subject for admin actions).</summary>
    public string? Account { get; init; }

    /// <summary>Source network address for logon-type events, when present.</summary>
    public string? SourceAddress { get; init; }

    /// <summary>Event level, e.g. Information, Warning, Error, Critical.</summary>
    public string Level { get; init; } = "Information";

    /// <summary>
    /// Additional structured fields pulled from the event's EventData/UserData,
    /// keyed by field name (e.g. "ServiceFileName", "LogonType", "TargetSid").
    /// Lookups are case-insensitive.
    /// </summary>
    public IReadOnlyDictionary<string, string> Data { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Convenience accessor for a Data field; returns null when absent.</summary>
    public string? GetData(string key) => Data.TryGetValue(key, out var value) ? value : null;

    /// <summary>
    /// Normalizes an account name or source address read from a log export. Windows writes
    /// <c>-</c> when a field has no value (for example <c>IpAddress</c> on a local 4625), so
    /// <c>-</c>, empty and whitespace-only values become <c>null</c> instead of a shared
    /// placeholder that would merge unrelated events into one group.
    /// </summary>
    public static string? NormalizeIdentity(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrEmpty(trimmed) || trimmed == "-" ? null : trimmed;
    }
}
