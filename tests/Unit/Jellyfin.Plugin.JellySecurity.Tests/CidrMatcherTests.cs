using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class CidrMatcherTests
{
    [Fact]
    public void Matches_SingleAddress()
    {
        Assert.True(CidrMatcher.Matches("10.0.0.8", "10.0.0.8, 10.0.0.1"));
        Assert.False(CidrMatcher.Matches("10.0.0.9", "10.0.0.8"));
    }

    [Fact]
    public void Matches_Cidr()
    {
        Assert.True(CidrMatcher.Matches("192.168.1.40", "192.168.1.0/24"));
        Assert.False(CidrMatcher.Matches("192.168.2.40", "192.168.1.0/24"));
    }

    [Fact]
    public void EmptyList_NeverMatches()
    {
        Assert.False(CidrMatcher.Matches("10.0.0.1", ""));
        Assert.False(CidrMatcher.Matches("10.0.0.1", null));
    }
}
