using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class IpNormalizerTests
{
    [Theory]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::ffff:192.168.1.10", "192.168.1.10")]
    [InlineData(" 10.0.0.8 ", "10.0.0.8")]
    public void Normalize_KnownForms(string input, string expected)
    {
        Assert.Equal(expected, IpNormalizer.Normalize(input));
    }

    [Fact]
    public void Loopback_IsDetected()
    {
        Assert.True(IpNormalizer.IsLoopback("127.0.0.1"));
        Assert.True(IpNormalizer.IsLoopback("::1"));
        Assert.False(IpNormalizer.IsLoopback("8.8.8.8"));
    }
}
