using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class AdminRestrictionTests
{
    [Fact]
    public void FailsOpen_WhenNetworksEmpty()
    {
        var identity = new ClientIdentity("203.0.113.10", "203.0.113.10", SourceTrust.Verified, "direct", false);
        var decision = AdminRestriction.Evaluate(new PluginConfiguration { RestrictAdminNetworks = true }, identity);
        Assert.False(decision.Block);
    }

    [Fact]
    public void FailsOpen_WhenAddressUntrusted()
    {
        var identity = new ClientIdentity("203.0.113.10", "10.0.0.1", SourceTrust.Unknown, "spoof", false);
        var config = new PluginConfiguration
        {
            RestrictAdminNetworks = true,
            AdminNetworks = "10.8.0.0/24"
        };
        Assert.False(AdminRestriction.Evaluate(config, identity).Block);
    }

    [Fact]
    public void Blocks_MappedAdmin_FromOutside()
    {
        var identity = new ClientIdentity("203.0.113.10", "203.0.113.10", SourceTrust.Verified, "direct", false);
        var config = new PluginConfiguration
        {
            RestrictAdminNetworks = true,
            AdminNetworks = "10.8.0.0/24"
        };
        Assert.True(AdminRestriction.Evaluate(config, identity).Block);
    }
}
