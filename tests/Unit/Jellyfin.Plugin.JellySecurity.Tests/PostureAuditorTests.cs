using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Engine;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class PostureAuditorTests
{
    [Fact]
    public void Flags_UnprovenPreAuth_AndEmptyAdminRestriction()
    {
        var findings = PostureAuditor.Audit(
            new PluginConfiguration { RestrictAdminNetworks = true },
            []);
        Assert.Contains(findings, f => f.Id == "preauth-unproven" && !f.Proven);
        Assert.Contains(findings, f => f.Id == "admin-restriction-empty");
    }
}
