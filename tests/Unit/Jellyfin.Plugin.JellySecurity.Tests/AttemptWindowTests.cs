using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class AttemptWindowTests
{
    [Fact]
    public void Counts_InsideWindow_AndDropsOldHits()
    {
        var window = new AttemptWindow(TimeSpan.FromMinutes(5));
        var start = DateTimeOffset.Parse("2026-10-09T12:00:00Z");
        Assert.Equal(1, window.Record(start));
        Assert.Equal(2, window.Record(start.AddMinutes(1)));
        Assert.Equal(2, window.Record(start.AddMinutes(6)));
        Assert.Equal(1, window.Record(start.AddMinutes(12)));
    }
}
