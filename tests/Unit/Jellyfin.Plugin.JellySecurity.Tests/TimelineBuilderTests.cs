using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Jellyfin.Plugin.JellySecurity.Core.Reports;
using Xunit;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class TimelineBuilderTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    private static SecurityEvent Ev(string address, string outcome, string? username = null, string? riskBand = null, int minutesOffset = 0)
    {
        return new SecurityEvent
        {
            Kind = "LoginAttempt",
            Outcome = outcome,
            Username = username,
            Address = address,
            TimestampUtc = BaseTime.AddMinutes(minutesOffset),
            RiskBand = riskBand,
            Message = outcome + " sign-in"
        };
    }

    private static BanRecord Ban(string target, BanKind kind, int minutesOffset = 0)
    {
        return new BanRecord
        {
            Target = target,
            Kind = kind,
            Reason = "test ban",
            CreatedUtc = BaseTime.AddMinutes(minutesOffset),
            ExpiresUtc = BaseTime.AddMinutes(minutesOffset + 60),
            Strike = 1,
            CreatedBy = "test"
        };
    }

    private static SecurityIncident Inc(string subject, string detectorId, int minutesOffset = 0)
    {
        return new SecurityIncident
        {
            Subject = subject,
            DetectorId = detectorId,
            RiskBand = "High",
            Explanation = "test pattern",
            FirstUtc = BaseTime.AddMinutes(minutesOffset),
            LastUtc = BaseTime.AddMinutes(minutesOffset),
            Count = 1
        };
    }

    [Fact]
    public void ReturnsEmpty_WhenNoEvents()
    {
        var stories = TimelineBuilder.Build([], [], []);
        Assert.Empty(stories);
    }

    [Fact]
    public void ExcludesAddresses_WithOnlySuccessfulSignIns()
    {
        var events = new[]
        {
            Ev("203.0.113.1", "Succeeded", "alice"),
            Ev("203.0.113.1", "Succeeded", "alice")
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Empty(stories);
    }

    [Fact]
    public void IncludesAddresses_WithAtLeastOneFailure()
    {
        var events = new[]
        {
            Ev("203.0.113.5", "Failed", "admin"),
            Ev("203.0.113.5", "Succeeded", "admin", minutesOffset: 1)
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        Assert.Equal("203.0.113.5", stories[0].Subject);
        Assert.Equal(2, stories[0].AttemptCount);
        Assert.Equal(1, stories[0].FailedCount);
        Assert.Equal(0, stories[0].BlockedCount);
    }

    [Fact]
    public void GroupsByAddress_NotByUsername()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "alice"),
            Ev("203.0.113.10", "Failed", "bob"),
            Ev("203.0.113.10", "Failed", "admin")
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        Assert.Equal(3, stories[0].DistinctUsernames);
    }

    [Fact]
    public void SeparateAddresses_ProduceSeparateStories()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin"),
            Ev("203.0.113.20", "Failed", "admin")
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Equal(2, stories.Count);
    }

    [Fact]
    public void LinksBanToStory_WhenBanTargetMatchesAddress()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin"),
            Ev("203.0.113.10", "Blocked", "admin", minutesOffset: 1)
        };
        var bans = new[] { Ban("203.0.113.10", BanKind.AutomaticTemporary, 2) };

        var stories = TimelineBuilder.Build(events, [], bans);
        Assert.Single(stories);
        Assert.True(stories[0].WasBanned);
        Assert.Equal("AutomaticTemporary", stories[0].BanKind);
    }

    [Fact]
    public void LinksCidrBan_WhenAddressIsInsideRange()
    {
        var events = new[]
        {
            Ev("203.0.113.50", "Failed", "admin")
        };
        var bans = new[] { Ban("203.0.113.0/24", BanKind.Cidr, 1) };

        var stories = TimelineBuilder.Build(events, [], bans);
        Assert.Single(stories);
        Assert.True(stories[0].WasBanned);
        Assert.Equal("Cidr", stories[0].BanKind);
    }

    [Fact]
    public void DoesNotLinkBan_WhenBanTargetIsDifferentAddress()
    {
        var events = new[] { Ev("203.0.113.10", "Failed", "admin") };
        var bans = new[] { Ban("198.51.100.1", BanKind.Manual, 1) };

        var stories = TimelineBuilder.Build(events, [], bans);
        Assert.Single(stories);
        Assert.False(stories[0].WasBanned);
    }

    [Fact]
    public void StepsAreInChronologicalOrder()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin", minutesOffset: 5),
            Ev("203.0.113.10", "Failed", "admin", minutesOffset: 1),
            Ev("203.0.113.10", "Failed", "admin", minutesOffset: 3)
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        var steps = stories[0].Steps;
        Assert.Equal(3, steps.Count);
        Assert.True(steps[0].TimestampUtc <= steps[1].TimestampUtc);
        Assert.True(steps[1].TimestampUtc <= steps[2].TimestampUtc);
    }

    [Fact]
    public void BanStepAppears_InTimeline()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin", minutesOffset: 0),
            Ev("203.0.113.10", "Blocked", "admin", minutesOffset: 1)
        };
        var bans = new[] { Ban("203.0.113.10", BanKind.AutomaticTemporary, 2) };

        var stories = TimelineBuilder.Build(events, [], bans);
        var banStep = stories[0].Steps.FirstOrDefault(s => s.Type == "Ban");
        Assert.NotNull(banStep);
        Assert.Contains("AutomaticTemporary ban applied", banStep!.Message);
    }

    [Fact]
    public void DetectorsFromIncidents_AreIncluded()
    {
        var events = new[] { Ev("203.0.113.10", "Failed", "admin") };
        var incidents = new[]
        {
            Inc("203.0.113.10", "BruteForce"),
            Inc("203.0.113.10", "PasswordSpray")
        };

        var stories = TimelineBuilder.Build(events, incidents, []);
        Assert.Single(stories);
        Assert.Contains("BruteForce", stories[0].Detectors);
        Assert.Contains("PasswordSpray", stories[0].Detectors);
    }

    [Fact]
    public void HighestRiskBand_ReflectsMostSevereEvent()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin", riskBand: "Low"),
            Ev("203.0.113.10", "Failed", "admin", riskBand: "Critical", minutesOffset: 1),
            Ev("203.0.113.10", "Failed", "admin", riskBand: "Medium", minutesOffset: 2)
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        Assert.Equal("Critical", stories[0].HighestRiskBand);
    }

    [Fact]
    public void Duration_IsInstant_WhenSingleEvent()
    {
        var events = new[] { Ev("203.0.113.10", "Failed", "admin") };
        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        Assert.Equal("instant", stories[0].Duration);
    }

    [Fact]
    public void Duration_FormatsSeconds_WhenShortAttack()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin", minutesOffset: 0),
            Ev("203.0.113.10", "Failed", "admin", minutesOffset: 1)
        };
        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        Assert.Contains("s", stories[0].Duration);
    }

    [Fact]
    public void RespectsMaxStories_Limit()
    {
        var events = new List<SecurityEvent>();
        for (var i = 0; i < 10; i++)
        {
            events.Add(Ev($"203.0.113.{i}", "Failed", "admin"));
        }

        var stories = TimelineBuilder.Build(events, [], [], maxStories: 3);
        Assert.Equal(3, stories.Count);
    }

    [Fact]
    public void SortsByMostActive_First()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin"),
            Ev("203.0.113.20", "Failed", "admin"),
            Ev("203.0.113.20", "Failed", "admin", minutesOffset: 1),
            Ev("203.0.113.20", "Failed", "admin", minutesOffset: 2)
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Equal(2, stories.Count);
        // 203.0.113.20 has 3 attempts, 203.0.113.10 has 1
        Assert.Equal("203.0.113.20", stories[0].Subject);
        Assert.Equal(3, stories[0].AttemptCount);
        Assert.Equal(1, stories[1].AttemptCount);
    }

    [Fact]
    public void BlockedCount_TracksPluginBlocks()
    {
        var events = new[]
        {
            Ev("203.0.113.10", "Failed", "admin"),
            Ev("203.0.113.10", "Blocked", "admin", minutesOffset: 1),
            Ev("203.0.113.10", "Blocked", "admin", minutesOffset: 2)
        };

        var stories = TimelineBuilder.Build(events, [], []);
        Assert.Single(stories);
        Assert.Equal(2, stories[0].BlockedCount);
        Assert.Equal(1, stories[0].FailedCount);
    }

    [Fact]
    public void Ipv6PrefixBan_LinksToAddressInsidePrefix()
    {
        var events = new[] { Ev("2001:db8::1", "Failed", "admin") };
        var bans = new[] { Ban("2001:db8::/64", BanKind.AutomaticPrefix, 1) };

        var stories = TimelineBuilder.Build(events, [], bans);
        Assert.Single(stories);
        Assert.True(stories[0].WasBanned);
        Assert.Equal("AutomaticPrefix", stories[0].BanKind);
    }
}
