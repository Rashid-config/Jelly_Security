using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;
using Jellyfin.Plugin.JellySecurity.Integration;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class AccountCooldownPolicyTests
{
    [Fact]
    public void StaysOff_UntilEnabled()
    {
        var config = Ready();
        config.AccountCooldownEnabled = false;
        Assert.False(AccountCooldownPolicy.IsClearSpray(config, 6, 10));
        Assert.False(AccountCooldownPolicy.Blocks(config, AuthPathKind.Password, Verified(), ExceptionClass.None, true));
    }

    [Fact]
    public void OneAddress_IsNotAClearSpray()
    {
        Assert.False(AccountCooldownPolicy.IsClearSpray(Ready(), 1, 20));
    }

    [Fact]
    public void DistributedFailures_AreAClearSpray()
    {
        Assert.True(AccountCooldownPolicy.IsClearSpray(Ready(), 5, 8));
    }

    [Fact]
    public void Pause_BlocksPasswordSignIn_AndLeavesPlaybackAlone()
    {
        var config = Ready();
        var client = Verified();
        Assert.True(AccountCooldownPolicy.Blocks(config, AuthPathKind.Password, client, ExceptionClass.None, true));
        Assert.False(AccountCooldownPolicy.Blocks(config, AuthPathKind.None, client, ExceptionClass.None, true));
        Assert.False(AccountCooldownPolicy.Blocks(config, AuthPathKind.Password, client, ExceptionClass.Loopback, true));
    }

    [Fact]
    public void ActivePause_DoesNotExtend()
    {
        var tracker = new AccountCooldownTracker(100);
        var now = DateTimeOffset.Parse("2026-10-09T12:00:00Z");
        Assert.True(tracker.TryBegin("sam", now, now.AddMinutes(15), 5, "spray"));
        Assert.False(tracker.TryBegin("sam", now.AddMinutes(5), now.AddMinutes(30), 9, "later"));
        Assert.Equal(now.AddMinutes(15), tracker.Active("sam", now.AddMinutes(5))!.UntilUtc);
    }

    [Fact]
    public void Pause_ExpiresWithoutHelp()
    {
        var tracker = new AccountCooldownTracker(100);
        var now = DateTimeOffset.Parse("2026-10-09T12:00:00Z");
        tracker.TryBegin("sam", now, now.AddMinutes(15), 5, "spray");
        Assert.NotNull(tracker.Active("sam", now.AddMinutes(14)));
        Assert.Null(tracker.Active("sam", now.AddMinutes(15)));
        Assert.Empty(tracker.Snapshot(now.AddMinutes(15)));
    }

    [Fact]
    public void DistinctAddresses_Accumulate()
    {
        var tracker = new AccountCooldownTracker(100);
        var now = DateTimeOffset.Parse("2026-10-09T12:00:00Z");
        var window = TimeSpan.FromMinutes(15);
        tracker.RecordFailure("sam", "203.0.113.1", window, now);
        var levels = tracker.RecordFailure("sam", "203.0.113.2", window, now.AddMinutes(1));
        Assert.Equal(2, levels.DistinctIps);
        Assert.Equal(2, levels.Failures);
    }

    private static PluginConfiguration Ready()
    {
        return new PluginConfiguration
        {
            AccountCooldownEnabled = true,
            AccountCooldownMinutes = 15,
            AccountCooldownDistinctIps = 5,
            AccountCooldownFailures = 8,
            AccountCooldownWindowMinutes = 15,
            AccountCooldownSkipPrivilegedNetworks = true
        };
    }

    private static ClientIdentity Verified()
    {
        return new ClientIdentity("203.0.113.8", "203.0.113.8", SourceTrust.Verified, "direct", false);
    }
}
