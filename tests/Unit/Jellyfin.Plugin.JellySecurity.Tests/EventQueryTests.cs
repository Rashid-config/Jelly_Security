using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class EventQueryTests
{
    [Fact]
    public void Filters_ByOutcome_AndExportsCsvHeader()
    {
        var events = new[]
        {
            new SecurityEvent { Outcome = "Failed", Username = "a", TimestampUtc = DateTimeOffset.Parse("2026-10-09T12:00:00Z") },
            new SecurityEvent { Outcome = "Succeeded", Username = "b", TimestampUtc = DateTimeOffset.Parse("2026-10-09T13:00:00Z") }
        };

        var failed = EventQuery.Filter(events, outcome: "Failed");
        Assert.Single(failed);
        Assert.StartsWith("TimestampUtc,", EventQuery.ToCsv(failed));
    }
}
