using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Readers;

/// <summary>
/// Reads events exported as JSON, in the shape produced by PowerShell's
/// <c>Get-WinEvent | ConvertTo-Json</c> (a single object or an array of objects), plus a
/// flat/simplified schema for hand-authored samples. Field lookup is case-insensitive and
/// tolerant of several common aliases; anything else present on the object is preserved in
/// <see cref="EventRecord.Data"/>.
/// </summary>
public sealed class JsonEventReader : IEventReader
{
    private static readonly string[] EventIdKeys = { "EventId", "Id" };
    private static readonly string[] TimeKeys = { "TimeCreated", "TimeGenerated" };
    private static readonly string[] ProviderKeys = { "ProviderName", "Provider", "LogName" };
    private static readonly string[] ComputerKeys = { "MachineName", "Computer" };
    private static readonly string[] AccountKeys =
        { "Account", "TargetUserName", "SubjectUserName", "UserId", "AccountName" };
    private static readonly string[] SourceAddressKeys =
        { "SourceAddress", "IpAddress", "SourceNetworkAddress", "IpAddr" };
    private static readonly char[] OffsetSigns = { '+', '-' };
    private static readonly string[] LevelKeys = { "LevelDisplayName", "Level" };

    public IReadOnlyList<EventRecord> Read(TextReader input)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(input.ReadToEnd());
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Input is not valid JSON: {ex.Message}", ex);
        }

        using (doc)
        {
            var results = new List<EventRecord>();
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                var index = 0;
                foreach (var element in doc.RootElement.EnumerateArray())
                {
                    index++;
                    if (element.ValueKind != JsonValueKind.Object)
                    {
                        throw new InvalidDataException(
                            $"Event {index} in the JSON array is a {element.ValueKind}, not an object.");
                    }

                    results.Add(ParseRecord(element));
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                results.Add(ParseRecord(doc.RootElement));
            }
            else
            {
                throw new InvalidDataException(
                    $"Expected a JSON array of events or a single event object, got a {doc.RootElement.ValueKind}.");
            }

            return results;
        }
    }

    private static EventRecord ParseRecord(JsonElement element)
    {
        var eventId = GetInt(element, EventIdKeys) ?? throw new InvalidDataException(
            "Event JSON object is missing an EventId/Id field.");
        var time = GetDateTimeOffset(element, TimeKeys) ?? throw new InvalidDataException(
            "Event JSON object is missing a TimeCreated/TimeGenerated field.");

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var knownKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        knownKeys.UnionWith(EventIdKeys);
        knownKeys.UnionWith(TimeKeys);
        knownKeys.UnionWith(ProviderKeys);
        knownKeys.UnionWith(ComputerKeys);
        knownKeys.UnionWith(AccountKeys);
        knownKeys.UnionWith(SourceAddressKeys);
        knownKeys.UnionWith(LevelKeys);

        foreach (var prop in element.EnumerateObject())
        {
            if (knownKeys.Contains(prop.Name))
            {
                continue;
            }

            if (string.Equals(prop.Name, "Data", StringComparison.OrdinalIgnoreCase) &&
                prop.Value.ValueKind == JsonValueKind.Object)
            {
                foreach (var nested in prop.Value.EnumerateObject())
                {
                    data[nested.Name] = ValueToString(nested.Value);
                }

                continue;
            }

            if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
            {
                continue;
            }

            data[prop.Name] = ValueToString(prop.Value);
        }

        return new EventRecord
        {
            EventId = eventId,
            TimeCreated = time,
            Provider = GetString(element, ProviderKeys) ?? string.Empty,
            Computer = GetString(element, ComputerKeys) ?? string.Empty,
            Account = EventRecord.NormalizeIdentity(GetString(element, AccountKeys)),
            SourceAddress = EventRecord.NormalizeIdentity(GetString(element, SourceAddressKeys)),
            Level = GetString(element, LevelKeys) ?? "Information",
            Data = data,
        };
    }

    private static string ValueToString(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => string.Empty,
        _ => value.GetRawText(),
    };

    private static bool TryFind(JsonElement element, string[] keys, out JsonElement value)
    {
        foreach (var key in keys)
        {
            foreach (var prop in element.EnumerateObject())
            {
                if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase))
                {
                    value = prop.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    // Objects and arrays are not a usable name: Get-WinEvent's UserId, for example, serializes as a
    // SID object, which used to become the "account" as raw JSON text.
    private static string? GetString(JsonElement element, string[] keys) =>
        TryFind(element, keys, out var value) && value.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)
            ? ValueToString(value)
            : null;

    private static int? GetInt(JsonElement element, string[] keys)
    {
        if (!TryFind(element, keys, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt32(out var number) => number,
            JsonValueKind.Number => throw new InvalidDataException(
                $"Event ID {value.GetRawText()} is not a 32-bit integer."),
            JsonValueKind.String when int.TryParse(value.GetString(), out var parsed) => parsed,
            _ => null,
        };
    }

    private static DateTimeOffset? GetDateTimeOffset(JsonElement element, string[] keys)
    {
        if (!TryFind(element, keys, out var value))
        {
            return null;
        }

        var raw = value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText();
        if (raw is null)
        {
            return null;
        }

        // .NET's own ConvertTo-Json for DateTime produces "/Date(1700000000000)/" style strings
        // when using older PowerShell defaults; support both that and ISO 8601.
        if (raw.StartsWith("/Date(", StringComparison.Ordinal))
        {
            var close = raw.IndexOf(')', StringComparison.Ordinal);
            if (close < 0)
            {
                return null;
            }

            // The body may carry a "+0100"-style suffix after the milliseconds; it does not change
            // the instant, which is always UTC milliseconds since the epoch.
            var digits = raw["/Date(".Length..close];
            var suffix = digits.IndexOfAny(OffsetSigns, 1);
            if (suffix > 0)
            {
                digits = digits[..suffix];
            }

            return long.TryParse(digits, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var millis) &&
                   millis >= -62135596800000 && millis <= 253402300799999
                ? DateTimeOffset.FromUnixTimeMilliseconds(millis)
                : null;
        }

        return DateTimeOffset.TryParse(
            raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : null;
    }
}
