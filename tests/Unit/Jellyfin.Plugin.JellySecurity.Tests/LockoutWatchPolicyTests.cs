using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class LockoutWatchPolicyTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(null)]
    public void NonPositiveLimit_IsNotConfigured(int? limit)
    {
        Assert.Equal(LockoutWatchPolicy.NotConfigured, LockoutWatchPolicy.Classify(20, limit, 5));
        Assert.False(LockoutWatchPolicy.LockoutConfigured(limit));
    }

    [Fact]
    public void OwnLimit_NotAFixedNumber()
    {
        Assert.Equal(LockoutWatchPolicy.Clear, LockoutWatchPolicy.Classify(19, 25, 5));
        Assert.Equal(LockoutWatchPolicy.Approaching, LockoutWatchPolicy.Classify(1, 6, 5));
        Assert.Equal(LockoutWatchPolicy.Clear, LockoutWatchPolicy.Classify(1, 10, 5));
    }

    [Fact]
    public void RemainingFive_OnALimitOf25_IsApproaching()
    {
        Assert.Equal(LockoutWatchPolicy.Approaching, LockoutWatchPolicy.Classify(20, 25, 5));
        Assert.Equal(5, LockoutWatchPolicy.Remaining(20, 25));
    }

    [Fact]
    public void AttemptsAtTheAccountLimit_AreReached()
    {
        Assert.Equal(LockoutWatchPolicy.Reached, LockoutWatchPolicy.Classify(25, 25, 5));
        Assert.Equal(LockoutWatchPolicy.Reached, LockoutWatchPolicy.Classify(30, 25, 5));
    }

    [Fact]
    public void SmallLimit_WarnsWhenRemainingFitsInsideTheMargin()
    {
        Assert.Equal(LockoutWatchPolicy.Approaching, LockoutWatchPolicy.Classify(0, 3, 5));
    }

    [Fact]
    public void MissingSettings_UseTheDefaults()
    {
        Assert.Equal(5, LockoutWatchPolicy.WarnWithin(0));
        Assert.Equal(60, LockoutWatchPolicy.CooldownMinutes(0));
        Assert.Equal(LockoutWatchPolicy.Clear, LockoutWatchPolicy.Classify(19, 25, 0));
    }
}
