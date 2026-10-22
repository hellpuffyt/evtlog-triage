using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>Shared helpers for the burst-style rules (brute force, explicit-credential bursts, etc.).</summary>
internal static class SlidingWindow
{
    /// <summary>
    /// Scans a chronologically-sorted sequence for the earliest non-overlapping windows of length
    /// &lt;= <paramref name="window"/> containing at least <paramref name="threshold"/> events.
    /// The window is inclusive at both ends: an event exactly <paramref name="window"/> after the
    /// window's first event is still considered part of that window.
    /// Once a window reaches the threshold it is extended to every later event still within
    /// <paramref name="window"/> of its first event, so the burst reports the full volume.
    /// After a burst is emitted, scanning resumes strictly after it, so bursts never overlap.
    /// </summary>
    public static IEnumerable<IReadOnlyList<EventRecord>> FindBursts(
        IReadOnlyList<EventRecord> sorted, int threshold, TimeSpan window)
    {
        if (threshold < 1)
        {
            yield break;
        }

        var left = 0;
        for (var right = 0; right < sorted.Count; right++)
        {
            while (sorted[right].TimeCreated - sorted[left].TimeCreated > window)
            {
                left++;
            }

            if (right - left + 1 >= threshold)
            {
                // Extend the burst over every later event that still falls inside the window that
                // started at `left`, so one burst of 40 events is reported once with all 40 events
                // rather than as four 10-event findings that each understate the volume.
                while (right + 1 < sorted.Count &&
                       sorted[right + 1].TimeCreated - sorted[left].TimeCreated <= window)
                {
                    right++;
                }

                yield return sorted.Skip(left).Take(right - left + 1).ToList();
                left = right + 1;
            }
        }
    }

    /// <summary>Groups events by a key, ignoring null/empty keys, preserving chronological order within each group.</summary>
    public static Dictionary<string, List<EventRecord>> GroupByKey(
        IEnumerable<EventRecord> events, Func<EventRecord, string?> keySelector)
    {
        var groups = new Dictionary<string, List<EventRecord>>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            var key = keySelector(evt);
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            if (!groups.TryGetValue(key, out var list))
            {
                list = new List<EventRecord>();
                groups[key] = list;
            }

            list.Add(evt);
        }

        return groups;
    }
}
