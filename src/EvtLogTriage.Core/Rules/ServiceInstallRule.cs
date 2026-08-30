using System.Collections.Generic;
using System.Linq;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Rules;

/// <summary>
/// Flags service installation (7045) whose binary path looks suspicious: temp directories,
/// user profile paths, downloads, or ProgramData rather than Program Files/System32. Malware
/// and lateral-movement tooling frequently installs itself as a service from a writable,
/// unmonitored location; legitimate software almost always installs under Program Files.
/// </summary>
public sealed class ServiceInstallRule : IDetectionRule
{
    public string RuleId => "SERVICE-INSTALL";
    public string Name => "Service installed from suspicious path";

    public IEnumerable<Finding> Evaluate(IReadOnlyList<EventRecord> events, TriageOptions options)
    {
        var installs = events.Where(e => e.EventId == EventIds.ServiceInstalled).OrderBy(e => e.TimeCreated);

        foreach (var evt in installs)
        {
            var path = evt.GetData("ServiceFileName") ?? evt.GetData("ImagePath");
            if (path is null || !IsSuspicious(path, options))
            {
                continue;
            }

            var serviceName = evt.GetData("ServiceName") ?? "(unknown)";

            yield return new Finding
            {
                RuleId = RuleId,
                RuleName = Name,
                Severity = Severity.High,
                WindowStart = evt.TimeCreated,
                WindowEnd = evt.TimeCreated,
                Events = new[] { evt },
                Summary = $"Service '{serviceName}' installed from suspicious path '{path}'",
                Explanation = $"A new service '{serviceName}' was installed (Event ID 7045) with binary path " +
                    $"'{path}', which is a temp directory, user profile path, or other writable location " +
                    "outside the normal Program Files/System32 install locations. Malware and lateral-movement " +
                    "tooling frequently persist by installing a service from exactly this kind of location.",
                Recommendation = "Inspect the binary at that path, confirm it is expected software, and if not, " +
                    "remove the service and investigate how it was installed.",
            };
        }
    }

    private static bool IsSuspicious(string path, TriageOptions options) =>
        options.SuspiciousServicePathFragments.Any(
            fragment => path.Contains(fragment, StringComparison.OrdinalIgnoreCase));
}
