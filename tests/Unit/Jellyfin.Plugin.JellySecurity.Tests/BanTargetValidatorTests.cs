using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class BanTargetValidatorTests
{
    [Theory]
    [InlineData("10.0.0.8", true)]
    [InlineData("192.168.1.0/24", true)]
    [InlineData("2001:db8::1", true)]
    [InlineData("not-an-ip", false)]
    [InlineData("0.0.0.0/0", false)]
    [InlineData("::/0", false)]
    [InlineData("10.0.0.0/99", false)]
    public void Validates_AddressesAndCidr(string target, bool ok)
    {
        Assert.Equal(ok, BanTargetValidator.Validate(target).Ok);
    }

    [Fact]
    public void Normalizes_Ipv4Mapped()
    {
        var result = BanTargetValidator.Validate("::ffff:192.168.1.10");
        Assert.True(result.Ok);
        Assert.Equal("192.168.1.10", result.Normalized);
    }
}
