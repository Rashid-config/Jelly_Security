using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ProxyTrustValidatorTests
{
    [Fact]
    public void IgnoresForwardedHeader_WhenTrustIsOff()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.8");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.10";
        var identity = new ProxyTrustValidator().Resolve(context, new PluginConfiguration { TrustForwardedFor = false });
        Assert.Equal("10.0.0.8", identity.Address);
        Assert.False(identity.UsedForwardedHeader);
    }

    [Fact]
    public void RejectsForwardedHeader_FromUnknownSocket()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.8");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.10";
        var config = new PluginConfiguration
        {
            TrustForwardedFor = true,
            KnownProxies = "127.0.0.1"
        };
        var identity = new ProxyTrustValidator().Resolve(context, config);
        Assert.Equal(SourceTrust.Unknown, identity.Trust);
        Assert.Equal("10.0.0.8", identity.Address);
    }

    [Fact]
    public void AcceptsForwardedHeader_FromKnownProxy()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.10";
        var config = new PluginConfiguration
        {
            TrustForwardedFor = true,
            KnownProxies = "127.0.0.1"
        };
        var identity = new ProxyTrustValidator().Resolve(context, config);
        Assert.Equal(SourceTrust.Verified, identity.Trust);
        Assert.Equal("203.0.113.10", identity.Address);
    }

    [Fact]
    public void MultiHopForwardedHeader_IsAmbiguous()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.10, 10.0.0.1";
        var config = new PluginConfiguration
        {
            TrustForwardedFor = true,
            KnownProxies = "127.0.0.1"
        };
        var identity = new ProxyTrustValidator().Resolve(context, config);
        Assert.True(identity.AmbiguousForwardedChain);
        Assert.Equal(SourceTrust.Warning, identity.Trust);
        Assert.Equal(2, identity.ForwardedHopCount);
    }

    [Fact]
    public void FakeLeftHop_IsRejected_RightmostNonProxyIsClient()
    {
        // Attacker behind a trusted proxy sends a fake XFF header.
        // nginx with $proxy_add_x_forwarded_for appends the real client,
        // producing: "fake.attacker.ip, real.client.ip".
        // The rightmost non-proxy hop (real client) is used, and the
        // leftover non-proxy to the left (the fake) marks it ambiguous.
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        context.Request.Headers["X-Forwarded-For"] = "1.2.3.4, 203.0.113.99";
        var config = new PluginConfiguration
        {
            TrustForwardedFor = true,
            KnownProxies = "127.0.0.1"
        };
        var identity = new ProxyTrustValidator().Resolve(context, config);
        Assert.Equal("203.0.113.99", identity.Address);
        Assert.True(identity.AmbiguousForwardedChain);
        Assert.Equal(SourceTrust.Warning, identity.Trust);
    }

    [Fact]
    public void TwoTrustedProxies_ClientIsLeftmostNonProxy()
    {
        // Two proxies: client → proxy1 → proxy2 → us
        // XFF = [client, proxy1], socket = proxy2
        // Walking right to left: proxy1 is known → skip, client is not → Verified
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.2");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.50, 10.0.0.1";
        var config = new PluginConfiguration
        {
            TrustForwardedFor = true,
            KnownProxies = "10.0.0.1, 10.0.0.2"
        };
        var identity = new ProxyTrustValidator().Resolve(context, config);
        Assert.Equal("203.0.113.50", identity.Address);
        Assert.False(identity.AmbiguousForwardedChain);
        Assert.Equal(SourceTrust.Verified, identity.Trust);
    }

    [Fact]
    public void AutomaticBans_StayOff_InMonitorOnly()
    {
        var config = new PluginConfiguration
        {
            Mode = ProtectionMode.MonitorOnly,
            AutomaticIpBans = true
        };
        var identity = new ClientIdentity("203.0.113.10", "127.0.0.1", SourceTrust.Verified, "test", false);
        Assert.False(new ProxyTrustValidator().AllowsAutomaticIpBans(config, identity));
    }
}
