using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Tests;

/// <summary>Small helper for building synthetic EventRecord instances in tests.</summary>
internal static class TestEvents
{
    public static readonly DateTimeOffset Base = new(2026, 3, 2, 9, 0, 0, TimeSpan.Zero); // a Monday

    public static EventRecord Make(
        int id,
        DateTimeOffset time,
        string? account = null,
        string? source = null,
        string computer = "HOST1",
        Dictionary<string, string>? data = null) =>
        new()
        {
            EventId = id,
            TimeCreated = time,
            Provider = "Microsoft-Windows-Security-Auditing",
            Computer = computer,
            Account = account,
            SourceAddress = source,
            Level = "Information",
            Data = data ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        };
}
