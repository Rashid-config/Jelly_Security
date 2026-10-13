using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class HoneypotBanPolicyTests
{
    [Fact]
    public void StaysOff_UntilEnabled()
    {
        var decision = HoneypotBanPolicy.Evaluate(false, true, false, true, true, ExceptionClass.None);
        Assert.False(decision.Ban);
    }

    [Fact]
    public void RealUserName_DoesNotArm()
    {
        var decision = HoneypotBanPolicy.Evaluate(true, true, true, true, true, ExceptionClass.None);
        Assert.False(decision.Ban);
    }

    [Fact]
    public void UnusedName_BansVerifiedIpv4()
    {
        var decision = HoneypotBanPolicy.Evaluate(true, true, false, true, true, ExceptionClass.None);
        Assert.True(decision.Ban);
    }

    [Theory]
    [InlineData(false, true, ExceptionClass.None)]
    [InlineData(true, false, ExceptionClass.None)]
    [InlineData(true, true, ExceptionClass.Administrative)]
    [InlineData(true, true, ExceptionClass.Loopback)]
    public void Refuses_Unverified_Ipv6_AndPrivilegedNetworks(bool verified, bool ipv4, ExceptionClass exception)
    {
        var decision = HoneypotBanPolicy.Evaluate(true, true, false, verified, ipv4, exception);
        Assert.False(decision.Ban);
    }

    [Fact]
    public void Duration_DefaultsToSixty_AndCapsAtOneDay()
    {
        Assert.Equal(60, HoneypotBanPolicy.DurationMinutes(0));
        Assert.Equal(1440, HoneypotBanPolicy.DurationMinutes(5000));
    }
}
