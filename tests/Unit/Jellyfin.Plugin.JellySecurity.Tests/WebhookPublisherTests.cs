using System.Net;
using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class WebhookPublisherTests
{
    [Theory]
    // IP literals keep these tests free of DNS lookups so they cannot flake on CI.
    [InlineData("http://203.0.113.5:9000/hook", true)]
    [InlineData("https://198.51.100.7/hook", true)]
    [InlineData("ftp://example.com/hook", false)]
    [InlineData("not-a-url", false)]
    [InlineData("", false)]
    public void Accepts_PublicHttpOrHttpsUrlsOnly(string url, bool ok)
    {
        Assert.Equal(ok, WebhookPublisher.IsSafeUrl(url));
    }

    [Theory]
    [InlineData("http://127.0.0.1:9000/hook", false)]
    [InlineData("http://169.254.169.254/latest/meta-data/", false)]
    [InlineData("http://10.0.0.1:9000/hook", false)]
    [InlineData("http://172.16.0.1:9000/hook", false)]
    [InlineData("http://192.168.1.1:9000/hook", false)]
    [InlineData("http://[::1]:9000/hook", false)]
    [InlineData("http://[fe80::1]:9000/hook", false)]
    [InlineData("http://[fc00::1]:9000/hook", false)]
    [InlineData("http://localhost:9000/hook", false)]
    public void Rejects_PrivateAndLoopbackAddresses(string url, bool ok)
    {
        Assert.Equal(ok, WebhookPublisher.IsSafeUrl(url));
    }

    [Theory]
    [InlineData("203.0.113.1", true)]
    [InlineData("198.51.100.1", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("192.168.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.1", false)]
    public void IsPublicAddress_ClassifiesCorrectly(string ip, bool expected)
    {
        var address = IPAddress.Parse(ip);
        Assert.Equal(expected, WebhookPublisher.IsPublicAddress(address));
    }
}
