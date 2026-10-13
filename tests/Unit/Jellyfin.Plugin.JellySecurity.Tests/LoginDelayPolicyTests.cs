using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;
using Jellyfin.Plugin.JellySecurity.Integration;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class LoginDelayPolicyTests
{
    [Fact]
    public void StaysOff_UntilEnabled()
    {
        var decision = LoginDelayPolicy.Evaluate(new PluginConfiguration(), 4);
        Assert.Equal(TimeSpan.Zero, decision.Delay);
    }

    [Fact]
    public void FirstAttempts_StayImmediate()
    {
        var decision = LoginDelayPolicy.Evaluate(Enabled(), 0);
        Assert.Equal(TimeSpan.Zero, decision.Delay);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 3)]
    [InlineData(3, 5)]
    [InlineData(9, 5)]
    public void Ladder_IsOneThenThreeThenFive(int priorFailures, int expectedSeconds)
    {
        var decision = LoginDelayPolicy.Evaluate(Enabled(), priorFailures);
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), decision.Delay);
    }

    [Fact]
    public void Ceiling_CapsALongerStep()
    {
        var config = Enabled();
        config.PasswordDelayStepsSeconds = "1,3,90";
        config.PasswordDelayCeilingSeconds = 5;
        var decision = LoginDelayPolicy.Evaluate(config, 3);
        Assert.Equal(TimeSpan.FromSeconds(5), decision.Delay);
        Assert.Equal(10, LoginDelayPolicy.CeilingSeconds(new PluginConfiguration { PasswordDelayCeilingSeconds = 999 }));
    }

    [Fact]
    public void Skips_UnverifiedAddresses_AndOtherRoutes()
    {
        var config = Enabled();
        var verified = new ClientIdentity("203.0.113.8", "203.0.113.8", SourceTrust.Verified, "direct", false);
        var unknown = verified with { Trust = SourceTrust.Unknown };
        Assert.True(LoginDelayPolicy.Applies(config, AuthPathKind.Password, verified, ExceptionClass.None));
        Assert.False(LoginDelayPolicy.Applies(config, AuthPathKind.Password, unknown, ExceptionClass.None));
        Assert.False(LoginDelayPolicy.Applies(config, AuthPathKind.QuickConnect, verified, ExceptionClass.None));
        Assert.False(LoginDelayPolicy.Applies(config, AuthPathKind.Password, verified, ExceptionClass.Loopback));
    }

    [Fact]
    public void Tracker_CountsInsideTheWindow_AndClears()
    {
        var tracker = new PasswordDelayTracker(100);
        var now = DateTimeOffset.Parse("2026-10-09T12:00:00Z");
        tracker.RecordFailure("203.0.113.8", TimeSpan.FromMinutes(15), now);
        tracker.RecordFailure("203.0.113.8", TimeSpan.FromMinutes(15), now.AddMinutes(1));
        Assert.Equal(2, tracker.Count("203.0.113.8", TimeSpan.FromMinutes(15), now.AddMinutes(2)));
        tracker.Clear("203.0.113.8");
        Assert.Equal(0, tracker.Count("203.0.113.8", TimeSpan.FromMinutes(15), now.AddMinutes(2)));
    }

    [Fact]
    public void PasswordPath_DoesNotIncludePlayback()
    {
        Assert.True(AuthPathClassifier.IsPasswordSignInPath("/Users/AuthenticateByName"));
        Assert.False(AuthPathClassifier.IsPasswordSignInPath("/Videos/123/stream"));
        Assert.False(AuthPathClassifier.IsPasswordSignInPath("/Users/ForgotPassword"));
    }

    private static PluginConfiguration Enabled()
    {
        return new PluginConfiguration
        {
            PasswordDelayEnabled = true,
            PasswordDelayStepsSeconds = "1,3,5",
            PasswordDelayCeilingSeconds = 5,
            PasswordDelayAfterFailures = 1,
            PasswordDelayWindowMinutes = 15,
            PasswordDelayRequireVerifiedAddress = true,
            PasswordDelaySkipPrivilegedNetworks = true
        };
    }
}
