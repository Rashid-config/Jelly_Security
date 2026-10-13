using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Engine;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class EnablementGateTests
{
    [Fact]
    public void MonitorOnly_NeverReady()
    {
        var status = EnablementGate.Evaluate(new PluginConfiguration
        {
            Mode = ProtectionMode.MonitorOnly,
            AutomaticIpBans = true
        });
        Assert.Equal("MonitorOnly", status.EngineState);
        Assert.False(status.AutomaticEnforcementReady);
        Assert.False(status.PreAuthLockoutProtectionProven);
    }

    [Fact]
    public void ForwardedWithoutProxies_IsUnknown()
    {
        var status = EnablementGate.Evaluate(new PluginConfiguration
        {
            Mode = ProtectionMode.Balanced,
            AutomaticIpBans = true,
            TrustForwardedFor = true,
            KnownProxies = string.Empty
        });
        Assert.Equal("Unknown", status.ProxyStatus);
        Assert.False(status.AutomaticEnforcementReady);
        Assert.Equal("Degraded", status.EngineState);
    }
}
