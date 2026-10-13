using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Xunit;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class Ipv6PrefixTests
{
    [Fact]
    public void ReturnsNull_ForNull()
    {
        Assert.Null(Ipv6Prefix.Of(null, 64));
    }

    [Fact]
    public void ReturnsNull_ForIpv4()
    {
        Assert.Null(Ipv6Prefix.Of("192.168.1.10", 64));
    }

    [Fact]
    public void ReturnsNull_ForIpv4MappedToIpv6()
    {
        Assert.Null(Ipv6Prefix.Of("::ffff:192.168.1.10", 64));
    }

    [Fact]
    public void ReturnsNull_ForOutOfRangePrefix()
    {
        Assert.Null(Ipv6Prefix.Of("2001:db8::1", 0));
        Assert.Null(Ipv6Prefix.Of("2001:db8::1", 129));
    }

    [Fact]
    public void ComputesSlash64_ForTypicalAddress()
    {
        var prefix = Ipv6Prefix.Of("2001:db8:1234:5678::abcd", 64);
        Assert.Equal("2001:db8:1234:5678::/64", prefix);
    }

    [Fact]
    public void ComputesSlash48()
    {
        var prefix = Ipv6Prefix.Of("2001:db8:1234:5678::abcd", 48);
        Assert.Equal("2001:db8:1234::/48", prefix);
    }

    [Fact]
    public void ComputesSlash128_ForFullAddress()
    {
        var prefix = Ipv6Prefix.Of("2001:db8::1", 128);
        Assert.Equal("2001:db8::1/128", prefix);
    }

    [Fact]
    public void MasksHostBits_AtNonByteBoundary()
    {
        // /52 = 6 full bytes + 4 bits. The 7th byte's low 4 bits must be zeroed.
        var prefix = Ipv6Prefix.Of("2001:db8:1234:5678:9abc::1", 52);
        Assert.Equal("2001:db8:1234:5000::/52", prefix);
    }

    [Fact]
    public void TwoAddressesInSameSlash64_ProduceSamePrefix()
    {
        var a = Ipv6Prefix.Of("2001:db8:1234:5678::1", 64);
        var b = Ipv6Prefix.Of("2001:db8:1234:5678::2", 64);
        Assert.Equal(a, b);
    }

    [Fact]
    public void TwoAddressesInDifferentSlash64_ProduceDifferentPrefix()
    {
        var a = Ipv6Prefix.Of("2001:db8:1234:5678::1", 64);
        var b = Ipv6Prefix.Of("2001:db8:1234:5679::1", 64);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void HandlesLinkLocal()
    {
        var prefix = Ipv6Prefix.Of("fe80::1234:5678", 64);
        Assert.Equal("fe80::/64", prefix);
    }
}
