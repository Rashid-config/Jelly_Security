using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class AlertAggregatorTests
{
    [Fact]
    public void Aggregates_DuringCooldown_ThenOpensNewIncident()
    {
        var config = new PluginConfiguration { AlertCooldownMinutes = 15 };
        var open = new List<SecurityIncident>();
        var signal = new DetectorSignal("password_spray", "1", "ip", "203.0.113.10", 8, "5m", "High", "High", "x", "spray");
        var assessment = new RiskAssessment("High", "High", "Alert", "alert", ["password_spray"], "spray");
        var start = DateTimeOffset.Parse("2026-10-09T12:00:00Z");

        var first = AlertAggregator.Record(open, signal, assessment, config, start);
        var again = AlertAggregator.Record(open, signal, assessment, config, start.AddMinutes(5));
        var later = AlertAggregator.Record(open, signal, assessment, config, start.AddMinutes(20));

        Assert.Same(first, again);
        Assert.Equal(2, first!.Count);
        Assert.Equal(2, open.Count);
        Assert.Equal(1, later!.Count);
    }

    [Fact]
    public void Clone_ProducesIndependentCopy()
    {
        var incident = new SecurityIncident
        {
            Id = "abc",
            DetectorId = "honeypot_username",
            Subject = "(honeypot)",
            RiskBand = "High",
            RecommendedAction = "Alert",
            Explanation = "test",
            Count = 5,
            FirstUtc = DateTimeOffset.Parse("2026-10-09T12:00:00Z"),
            LastUtc = DateTimeOffset.Parse("2026-10-09T12:05:00Z"),
            CooldownUntilUtc = DateTimeOffset.Parse("2026-10-09T12:15:00Z")
        };

        var copy = incident.Clone();
        Assert.NotSame(incident, copy);
        Assert.Equal(incident.Id, copy.Id);
        Assert.Equal(incident.Count, copy.Count);

        // Mutating the original must not affect the clone
        incident.Count = 99;
        Assert.Equal(5, copy.Count);
    }
}
