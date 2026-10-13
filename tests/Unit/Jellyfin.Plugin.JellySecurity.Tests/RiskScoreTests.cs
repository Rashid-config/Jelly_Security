using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class RiskScoreTests
{
    [Fact]
    public void UntrustedSource_IsCapped()
    {
        var assessment = new RiskAssessment("High", "Low", "Alert", "alert", ["x"], "test");
        Assert.True(RiskScore.Combine(assessment, 90, SourceTrust.Unknown) <= 40);
    }

    [Fact]
    public void Decay_Halves_InADay()
    {
        var start = DateTimeOffset.Parse("2026-10-09T00:00:00Z");
        Assert.Equal(40, RiskScore.Decay(80, start, start.AddHours(24)));
    }
}
