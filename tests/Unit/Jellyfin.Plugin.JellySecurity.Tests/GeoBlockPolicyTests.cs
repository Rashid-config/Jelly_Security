using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Geo;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class GeoBlockPolicyTests
{
    private static PluginConfiguration Config(params GeoBlockRule[] rules)
    {
        var config = new PluginConfiguration();
        config.GeoBlocks = rules.ToList();
        return config;
    }

    [Fact]
    public void Match_SingleAddress_ReturnsRowName()
    {
        var config = Config(new GeoBlockRule { Name = "XX", Ranges = "203.0.113.7", Enabled = true });
        Assert.Equal("XX", GeoBlockPolicy.Match(config, "203.0.113.7"));
    }

    [Fact]
    public void Match_CidrRange_ReturnsRowName()
    {
        var config = Config(new GeoBlockRule { Name = "YY", Ranges = "198.51.100.0/24", Enabled = true });
        Assert.Equal("YY", GeoBlockPolicy.Match(config, "198.51.100.40"));
        Assert.Null(GeoBlockPolicy.Match(config, "203.0.113.1"));
    }

    [Fact]
    public void DisabledRow_IsSkipped()
    {
        var config = Config(new GeoBlockRule { Name = "ZZ", Ranges = "203.0.113.0/24", Enabled = false });
        Assert.Null(GeoBlockPolicy.Match(config, "203.0.113.9"));
    }

    [Fact]
    public void EmptyAddress_ReturnsNull()
    {
        var config = Config(new GeoBlockRule { Name = "XX", Ranges = "0.0.0.0/0", Enabled = true });
        Assert.Null(GeoBlockPolicy.Match(config, null));
        Assert.Null(GeoBlockPolicy.Match(config, string.Empty));
    }

    [Fact]
    public void NoRows_ReturnsNull()
    {
        Assert.Null(GeoBlockPolicy.Match(Config(), "203.0.113.1"));
    }

    [Fact]
    public void InvalidEntries_AreIgnored_NotThrow()
    {
        var config = Config(new GeoBlockRule { Name = "XX", Ranges = "not-an-ip, garbage, 203.0.113.0/24", Enabled = true });
        Assert.Equal("XX", GeoBlockPolicy.Match(config, "203.0.113.5"));
    }

    [Fact]
    public void Separators_NewlinesAndSemicolons_Match()
    {
        var config = Config(new GeoBlockRule { Name = "XX", Ranges = "10.0.0.1\n10.0.0.2; 10.0.0.3", Enabled = true });
        Assert.Equal("XX", GeoBlockPolicy.Match(config, "10.0.0.3"));
    }

    [Fact]
    public void FirstEnabledMatch_Wins()
    {
        var config = Config(
            new GeoBlockRule { Name = "AA", Ranges = "198.51.100.0/24", Enabled = true },
            new GeoBlockRule { Name = "BB", Ranges = "203.0.113.0/24", Enabled = true });
        Assert.Equal("BB", GeoBlockPolicy.Match(config, "203.0.113.9"));
    }

    [Fact]
    public void BlankName_FallsBackToUnnamed()
    {
        var config = Config(new GeoBlockRule { Name = " ", Ranges = "203.0.113.0/24", Enabled = true });
        Assert.Equal("unnamed", GeoBlockPolicy.Match(config, "203.0.113.9"));
    }

    [Fact]
    public void CountRanges_CountsOnlyParseableEntries()
    {
        var rule = new GeoBlockRule { Ranges = "203.0.113.0/24, junk, 198.51.100.5" };
        Assert.Equal(2, GeoBlockPolicy.CountRanges(rule));
    }
}
