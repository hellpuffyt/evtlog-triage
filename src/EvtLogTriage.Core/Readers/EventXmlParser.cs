using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Readers;

/// <summary>
/// Converts one Windows event in its XML rendering (what <c>EventRecord.ToXml()</c>,
/// <c>wevtutil qe /f:xml</c> and Event Viewer's "Copy as XML" produce) into an
/// <see cref="EventRecord"/>.
/// </summary>
/// <remarks>
/// Fields are taken from the named <c>EventData/Data</c> elements (and <c>UserData</c> leaves,
/// which is where 1102 puts its subject), so the account and source address come from the field
/// that actually holds them for each event ID instead of from a fixed position. This class is
/// platform-neutral; only obtaining the XML from a live channel or .evtx file needs Windows.
/// </remarks>
public static class EventXmlParser
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    /// <summary>Parses one <c>&lt;Event&gt;</c> element.</summary>
    /// <exception cref="InvalidDataException">The XML is malformed or lacks EventID/TimeCreated.</exception>
    public static EventRecord Parse(string xml)
    {
        XElement root;
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            root = XElement.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new InvalidDataException($"Event XML is malformed: {ex.Message}", ex);
        }

        var system = root.Element(Ns + "System")
            ?? throw new InvalidDataException("Event XML has no System element.");

        if (!int.TryParse(system.Element(Ns + "EventID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
        {
            throw new InvalidDataException("Event XML has no numeric System/EventID.");
        }

        var timeRaw = system.Element(Ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
        if (!DateTimeOffset.TryParse(timeRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time))
        {
            throw new InvalidDataException("Event XML has no valid System/TimeCreated/@SystemTime.");
        }

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var eventData = root.Element(Ns + "EventData");
        if (eventData is not null)
        {
            var position = 0;
            foreach (var item in eventData.Elements(Ns + "Data"))
            {
                var name = item.Attribute("Name")?.Value;
                data[string.IsNullOrEmpty(name) ? $"Data{position}" : name] = item.Value;
                position++;
            }
        }

        var userData = root.Element(Ns + "UserData");
        if (userData is not null)
        {
            foreach (var leaf in userData.Descendants().Where(e => !e.HasElements))
            {
                data[leaf.Name.LocalName] = leaf.Value;
            }
        }

        return new EventRecord
        {
            EventId = eventId,
            TimeCreated = time,
            Provider = system.Element(Ns + "Provider")?.Attribute("Name")?.Value ?? string.Empty,
            Computer = system.Element(Ns + "Computer")?.Value ?? string.Empty,
            Account = EventRecord.NormalizeIdentity(AccountFor(eventId, data)),
            SourceAddress = EventRecord.NormalizeIdentity(Get(data, "IpAddress")),
            Level = LevelName(system.Element(Ns + "Level")?.Value),
            Data = data,
        };
    }

    // Which field names "the account" depends on the event: 4672 and 1102 describe the subject,
    // 4732 the member added to the group, the logon and account-management events the target.
    private static string? AccountFor(int eventId, Dictionary<string, string> data) => eventId switch
    {
        EventIds.SpecialPrivilegesAssigned or EventIds.AuditLogCleared => Get(data, "SubjectUserName"),
        EventIds.MemberAddedToSecurityGroup => Usable(Get(data, "MemberName")) ?? Get(data, "MemberSid"),
        _ => Usable(Get(data, "TargetUserName")) ?? Get(data, "SubjectUserName"),
    };

    private static string? Get(Dictionary<string, string> data, string key) =>
        data.TryGetValue(key, out var value) ? value : null;

    private static string? Usable(string? value) => EventRecord.NormalizeIdentity(value);

    private static string LevelName(string? level) => level switch
    {
        "1" => "Critical",
        "2" => "Error",
        "3" => "Warning",
        "5" => "Verbose",
        _ => "Information",
    };
}
