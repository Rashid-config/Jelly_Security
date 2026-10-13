using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ReconPolicyTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    private static ClientIdentity Verified(string address = "203.0.113.10")
        => new(address, address, SourceTrust.Verified, "direct", false);

    private static ClientIdentity Unverified(string address = "203.0.113.10")
        => new(address, "10.0.0.1", SourceTrust.Unknown, "spoof", false);

    // --- ThresholdCrossed ---

    [Fact]
    public void BelowThreshold_DoesNotCross()
    {
        var config = new PluginConfiguration();
        var a = new ReconAssessment(config.ReconFailedThreshold - 1, 0, 1);
        Assert.False(ReconPolicy.ThresholdCrossed(a, config));
    }

    [Fact]
    public void FailedThreshold_Crosses()
    {
        var config = new PluginConfiguration();
        var a = new ReconAssessment(config.ReconFailedThreshold, 0, 1);
        Assert.True(ReconPolicy.ThresholdCrossed(a, config));
    }

    [Fact]
    public void UnauthBreadth_Alone_DoesNotCross()
    {
        // Heavy unauth volume but only one path — a misbehaving client, not
        // enumeration. Breadth is required too.
        var config = new PluginConfiguration();
        var a = new ReconAssessment(0, config.ReconUnauthThreshold, config.ReconDistinctPathMin - 1);
        Assert.False(ReconPolicy.ThresholdCrossed(a, config));
    }

    [Fact]
    public void UnauthPlusBreadth_Crosses()
    {
        var config = new PluginConfiguration();
        var a = new ReconAssessment(0, config.ReconUnauthThreshold, config.ReconDistinctPathMin);
        Assert.True(ReconPolicy.ThresholdCrossed(a, config));
    }

    [Fact]
    public void Thresholds_NeverDivideToZero()
    {
        var config = new PluginConfiguration
        {
            ReconFailedThreshold = 0,
            ReconUnauthThreshold = 0,
            ReconDistinctPathMin = 0
        };
        var a = new ReconAssessment(1, 1, 1);
        Assert.True(ReconPolicy.ThresholdCrossed(a, config));
    }

    // --- MayEnforce ---

    [Fact]
    public void MayEnforce_Disabled_ReturnsFalse()
    {
        var config = new PluginConfiguration { ReconEnforce = false };
        Assert.False(ReconPolicy.MayEnforce(config, Verified()));
    }

    [Fact]
    public void MayEnforce_Unverified_ReturnsFalse()
    {
        var config = new PluginConfiguration { ReconEnforce = true };
        Assert.False(ReconPolicy.MayEnforce(config, Unverified()));
    }

    [Fact]
    public void MayEnforce_VerifiedAndEnabled_ReturnsTrue()
    {
        var config = new PluginConfiguration { ReconEnforce = true };
        Assert.True(ReconPolicy.MayEnforce(config, Verified()));
    }

    [Fact]
    public void MayEnforce_ExceptionNetwork_ReturnsFalse()
    {
        var config = new PluginConfiguration
        {
            ReconEnforce = true,
            AdminNetworks = "203.0.113.0/24"
        };
        Assert.False(ReconPolicy.MayEnforce(config, Verified()));
    }

    // --- ShouldBlock ---

    [Fact]
    public void ShouldBlock_NoWindow_Allows()
    {
        var config = new PluginConfiguration { ReconEnforce = true };
        Assert.False(ReconPolicy.ShouldBlock(config, Verified(), null, T0, out _));
    }

    [Fact]
    public void ShouldBlock_Disabled_Allows()
    {
        var config = new PluginConfiguration { ReconEnforce = false };
        var window = new ReconWindow();
        window.LimitUntil(T0.AddMinutes(10));
        Assert.False(ReconPolicy.ShouldBlock(config, Verified(), window, T0, out _));
    }

    [Fact]
    public void ShouldBlock_ActiveLimit_BlocksWithRetryAfter()
    {
        var config = new PluginConfiguration { ReconEnforce = true };
        var window = new ReconWindow();
        window.LimitUntil(T0.AddMinutes(10));
        Assert.True(ReconPolicy.ShouldBlock(config, Verified(), window, T0, out var seconds));
        Assert.Equal(600, seconds);
    }

    [Fact]
    public void ShouldBlock_ExpiredLimit_Allows()
    {
        var config = new PluginConfiguration { ReconEnforce = true };
        var window = new ReconWindow();
        window.LimitUntil(T0.AddMinutes(10));
        Assert.False(ReconPolicy.ShouldBlock(config, Verified(), window, T0.AddMinutes(11), out _));
    }

    [Fact]
    public void ShouldBlock_UnverifiedIdentity_Allows()
    {
        // A mid-cooldown trust change (or a spoofed forwarded header) must free
        // the address rather than 429 it.
        var config = new PluginConfiguration { ReconEnforce = true };
        var window = new ReconWindow();
        window.LimitUntil(T0.AddMinutes(10));
        Assert.False(ReconPolicy.ShouldBlock(config, Unverified(), window, T0, out _));
    }

    [Fact]
    public void ShouldBlock_ExceptionNetwork_Allows()
    {
        var config = new PluginConfiguration
        {
            ReconEnforce = true,
            AdminNetworks = "203.0.113.0/24"
        };
        var window = new ReconWindow();
        window.LimitUntil(T0.AddMinutes(10));
        Assert.False(ReconPolicy.ShouldBlock(config, Verified(), window, T0, out _));
    }
}
