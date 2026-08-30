namespace EvtLogTriage.Core.Models;

/// <summary>Ordered severity levels for findings, low to high.</summary>
public enum Severity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
