using System.Collections.Generic;
using System.IO;
using EvtLogTriage.Core.Models;

namespace EvtLogTriage.Core.Readers;

/// <summary>Reads events from some external representation into the platform-neutral EventRecord model.</summary>
public interface IEventReader
{
    IReadOnlyList<EventRecord> Read(TextReader input);
}
