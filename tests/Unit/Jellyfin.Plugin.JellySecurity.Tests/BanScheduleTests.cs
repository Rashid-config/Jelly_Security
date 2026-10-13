using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class BanScheduleTests
{
    [Fact]
    public void UsesConfiguredLadder_AndCapsAtLastStep()
    {
        var config = new PluginConfiguration { ProgressiveBanMinutes = "5,15,60,1440" };
        Assert.Equal(5, BanSchedule.DurationMinutes(config, 1));
        Assert.Equal(15, BanSchedule.DurationMinutes(config, 2));
        Assert.Equal(60, BanSchedule.DurationMinutes(config, 3));
        Assert.Equal(1440, BanSchedule.DurationMinutes(config, 4));
        Assert.Equal(1440, BanSchedule.DurationMinutes(config, 20));
    }

    [Fact]
    public void Fade_ResetsStrike_AfterQuietPeriod()
    {
        var config = new PluginConfiguration { EscalationResetDays = 7 };
        var state = new StrikeState { Count = 3, LastUtc = DateTimeOffset.Parse("2026-10-01T00:00:00Z") };
        var next = BanSchedule.NextStrike(state, config, DateTimeOffset.Parse("2026-10-09T00:00:00Z"));
        Assert.Equal(1, next);
    }
}
