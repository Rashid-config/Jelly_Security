using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Edge;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class EdgeSnippetTests
{
    [Fact]
    public void StaysOff_AndWritesNothing()
    {
        var result = EdgeSnippetBuilder.Build(new PluginConfiguration { EdgeSnippetEnabled = false }, []);
        Assert.False(result.Ready);
        Assert.Equal(string.Empty, result.Text);
        Assert.Contains("No proxy file was written", result.Note);
    }

    [Fact]
    public void UnknownTarget_IsRefused()
    {
        var result = EdgeSnippetBuilder.Build(Enabled("Apache", "127.0.0.1:8096"), []);
        Assert.False(result.Ready);
        Assert.Equal(string.Empty, result.Text);
    }

    [Theory]
    [InlineData("127.0.0.1:8096; include")]
    [InlineData("evil.example\nlimit_req")]
    [InlineData("http://127.0.0.1:8096")]
    [InlineData("127.0.0.1")]
    public void BadUpstream_IsRefused(string upstream)
    {
        var result = EdgeSnippetBuilder.Build(Enabled("Nginx", upstream), []);
        Assert.False(result.Ready);
        Assert.DoesNotContain("limit_req", result.Text);
    }

    [Fact]
    public void Nginx_LimitsSignIn_AndLeavesPlaybackOut()
    {
        var result = EdgeSnippetBuilder.Build(Enabled("Nginx", "[::1]:8096"), []);
        Assert.True(result.Ready);
        Assert.Contains("limit_req_zone", result.Text);
        Assert.Contains("rate=30r/m", result.Text);
        Assert.Contains("/Users/AuthenticateByName", result.Text);
        Assert.Contains("proxy_pass http://[::1]:8096;", result.Text);
        Assert.DoesNotContain("/Videos", result.Text);
        Assert.DoesNotContain("/Audio", result.Text);
        Assert.DoesNotContain("master.m3u8", result.Text);
        Assert.DoesNotContain("X-Jelly-Security-Edge-Key", result.Text);
        Assert.Contains("did not write this file", result.Text);
    }

    [Fact]
    public void Caddy_MatchesPostSignIn_AndNamesTheModule()
    {
        var result = EdgeSnippetBuilder.Build(Enabled("caddy", "jellyfin.internal:8096"), []);
        Assert.Equal("Caddy", result.Target);
        Assert.Contains("method POST", result.Text);
        Assert.Contains("github.com/mholt/caddy-ratelimit", result.Text);
        Assert.Contains("events 30", result.Text);
        Assert.DoesNotContain("/Audio", result.Text);
    }

    [Fact]
    public void Cloudflare_IsAnExpression_NotAnApiCall()
    {
        var result = EdgeSnippetBuilder.Build(Enabled("Cloudflare", "not-used"), []);
        Assert.True(result.Ready);
        Assert.Contains("http.request.method eq \"POST\"", result.Text);
        Assert.Contains("/Users/AuthenticateByName", result.Text);
        Assert.Contains("does not call the Cloudflare API", result.Text);
        Assert.Contains("Do not enable a site-wide bot challenge.", result.Text);
        Assert.DoesNotContain("proxy_pass", result.Text);
    }

    [Fact]
    public void Blocklist_EmbedsOnlyASafeKey()
    {
        var safe = Enabled("Nginx", "127.0.0.1:8096");
        safe.EdgeSnippetIncludeBlocklist = true;
        safe.EdgeChannelEnabled = true;
        safe.EdgeSharedKey = "abcdefghij123456";
        var withKey = EdgeSnippetBuilder.Build(safe, ["203.0.113.10", "not an ip\n", "0.0.0.0/0"]);
        Assert.True(withKey.BlocklistIncluded);
        Assert.Contains("X-Jelly-Security-Edge-Key: abcdefghij123456", withKey.Text);
        Assert.Contains("# deny 203.0.113.10;", withKey.Text);
        Assert.DoesNotContain("not an ip", withKey.Text);
        Assert.DoesNotContain("0.0.0.0/0", withKey.Text);
        Assert.Equal(1, withKey.DenyCount);

        safe.EdgeSharedKey = "bad key";
        var hidden = EdgeSnippetBuilder.Build(safe, ["203.0.113.10"]);
        Assert.False(hidden.BlocklistIncluded);
        Assert.DoesNotContain("bad key", hidden.Text);
        Assert.Contains("limit_req_zone", hidden.Text);
    }

    [Fact]
    public void DenyText_SkipsUnsafeTargets()
    {
        Assert.True(EdgeDenyText.TryFormat("nginx", ["198.51.100.8", "deny all;"], out var text));
        Assert.Contains("deny 198.51.100.8;", text);
        Assert.DoesNotContain("deny all", text);
        Assert.False(EdgeDenyText.TryFormat("apache", [], out _));
    }

    [Fact]
    public void ZeroRate_UsesTheDefault()
    {
        var config = Enabled("Nginx", null);
        config.EdgeSnippetAuthPerMinute = 0;
        config.EdgeSnippetBurst = 0;
        var result = EdgeSnippetBuilder.Build(config, []);
        Assert.Contains("rate=30r/m", result.Text);
        Assert.Contains("limit_req zone=jelly_security_auth nodelay;", result.Text);
        Assert.DoesNotContain("burst=", result.Text);
    }

    private static PluginConfiguration Enabled(string target, string? upstream)
    {
        return new PluginConfiguration
        {
            EdgeSnippetEnabled = true,
            EdgeSnippetTarget = target,
            EdgeSnippetUpstream = upstream ?? string.Empty
        };
    }
}
