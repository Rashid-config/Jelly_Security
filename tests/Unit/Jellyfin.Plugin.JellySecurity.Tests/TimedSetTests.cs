using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class TimedSetTests
{
    [Fact]
    public void CountsDistinctKeys_InsideWindowOnly()
    {
        var set = new TimedSet();
        var start = DateTimeOffset.Parse("2026-10-09T12:00:00Z");
        var window = TimeSpan.FromMinutes(5);
        Assert.Equal(1, set.Add("10.0.0.1", start, window));
        Assert.Equal(2, set.Add("10.0.0.2", start.AddMinutes(1), window));
        Assert.Equal(1, set.Add("10.0.0.3", start.AddMinutes(7), window));
    }
}
