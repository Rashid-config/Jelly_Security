using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Edge;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class EdgeAccessTests
{
    [Fact]
    public void Rejects_ShortKey_AndUnknownPeer()
    {
        var config = new PluginConfiguration
        {
            EdgeChannelEnabled = true,
            EdgeSharedKey = "short",
            EdgeRestrictToTrustedPeers = true
        };
        Assert.False(EdgeAccess.IsAuthorized(config, "short", "127.0.0.1"));
    }

    [Fact]
    public void Accepts_Loopback_WithLongKey()
    {
        var config = new PluginConfiguration
        {
            EdgeChannelEnabled = true,
            EdgeSharedKey = "1234567890abcdef",
            EdgeRestrictToTrustedPeers = true
        };
        Assert.True(EdgeAccess.IsAuthorized(config, "1234567890abcdef", "127.0.0.1"));
        Assert.False(EdgeAccess.IsAuthorized(config, "1234567890abcdef", "203.0.113.10"));
    }
}
