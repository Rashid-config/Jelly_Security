using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ThreatDetectorsTests
{
    private static ObservationContext Ctx(string? user, int failures, int ips, int names)
    {
        var identity = new ClientIdentity("203.0.113.10", "203.0.113.10", SourceTrust.Verified, "direct", false);
        return new ObservationContext(identity, user, "Failed", "/Users/AuthenticateByName", failures, ips, names, ExceptionClass.None, DateTimeOffset.UtcNow);
    }

    [Fact]
    public void BruteForce_Fires_OnRepeatedFailures()
    {
        var config = new PluginConfiguration { FailuresBeforeBan = 10 };
        var signals = ThreatDetectors.Evaluate(Ctx("alice", 10, 1, 1), config);
        Assert.Contains(signals, s => s.DetectorId == "single_ip_brute_force");
    }

    [Fact]
    public void Distributed_DoesNot_RecommendAccountLock()
    {
        var signals = ThreatDetectors.Evaluate(Ctx("alice", 3, 5, 1), new PluginConfiguration());
        var distributed = Assert.Single(signals, s => s.DetectorId == "distributed_account_attack");
        Assert.Contains("not an account lock", distributed.Explanation);
    }

    [Fact]
    public void Honeypot_Explanation_OmitsDecoyName()
    {
        var config = new PluginConfiguration { HoneypotUsername = "trap-user-secret" };
        var signals = ThreatDetectors.Evaluate(Ctx("trap-user-secret", 1, 1, 1), config);
        var honeypot = Assert.Single(signals, s => s.DetectorId == "honeypot_username");
        Assert.DoesNotContain("trap-user-secret", honeypot.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trap-user-secret", honeypot.Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DistributedSignal_HidesHoneypotName()
    {
        var config = new PluginConfiguration { HoneypotUsername = "trap-user-secret", DistributedIpCount = 5 };
        var signals = ThreatDetectors.Evaluate(Ctx("trap-user-secret", 3, 5, 1), config);
        var distributed = Assert.Single(signals, s => s.DetectorId == "distributed_account_attack");
        Assert.Equal("(honeypot)", distributed.Subject);
    }

    [Fact]
    public void AdminTarget_UsesListedNamesOnly()
    {
        var config = new PluginConfiguration { AdministrativeUsernames = "owner" };
        Assert.DoesNotContain(ThreatDetectors.Evaluate(Ctx("admin", 1, 1, 1), config), s => s.DetectorId == "administrative_account_targeting");
        Assert.Contains(ThreatDetectors.Evaluate(Ctx("owner", 1, 1, 1), config), s => s.DetectorId == "administrative_account_targeting");
    }

    [Fact]
    public void DisabledDetector_EmitsNothing()
    {
        var config = new PluginConfiguration { EnableBruteForceDetector = false, FailuresBeforeBan = 4 };
        var signals = ThreatDetectors.Evaluate(Ctx("alice", 10, 1, 1), config);
        Assert.DoesNotContain(signals, s => s.DetectorId == "single_ip_brute_force");
    }
}
