using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ExceptionPolicyTests
{
    private static PluginConfiguration Config() => new()
    {
        AdminNetworks = "10.0.0.0/24",
        TrustedNetworks = "192.168.1.0/24",
        MonitoringNetworks = "172.16.0.0/24"
    };

    [Fact]
    public void Classifies_ThreeNetworks_AndLoopback()
    {
        var config = Config();
        Assert.Equal(ExceptionClass.Loopback, ExceptionPolicy.Classify("127.0.0.1", config));
        Assert.Equal(ExceptionClass.Administrative, ExceptionPolicy.Classify("10.0.0.20", config));
        Assert.Equal(ExceptionClass.Trusted, ExceptionPolicy.Classify("192.168.1.40", config));
        Assert.Equal(ExceptionClass.Monitoring, ExceptionPolicy.Classify("172.16.0.8", config));
        Assert.Equal(ExceptionClass.None, ExceptionPolicy.Classify("203.0.113.10", config));
    }

    [Fact]
    public void ManualBan_DoesNotApply_ToAdminOrMonitoring()
    {
        Assert.False(ExceptionPolicy.AllowsManualBan(ExceptionClass.Administrative));
        Assert.False(ExceptionPolicy.AllowsManualBan(ExceptionClass.Monitoring));
        Assert.True(ExceptionPolicy.AllowsManualBan(ExceptionClass.Trusted));
        Assert.True(ExceptionPolicy.AllowsManualBan(ExceptionClass.None));
    }

    [Fact]
    public void AutomaticBan_Only_ForOrdinaryAddresses()
    {
        Assert.True(ExceptionPolicy.AllowsAutomaticBan(ExceptionClass.None));
        Assert.False(ExceptionPolicy.AllowsAutomaticBan(ExceptionClass.Trusted));
        Assert.False(ExceptionPolicy.AllowsAutomaticBan(ExceptionClass.Administrative));
    }
}
