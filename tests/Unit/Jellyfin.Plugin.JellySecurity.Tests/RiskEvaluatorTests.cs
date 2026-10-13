using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class RiskEvaluatorTests
{
    [Fact]
    public void DoesNot_DoubleCount_NameDiversity()
    {
        var signals = new[]
        {
            new DetectorSignal("password_spray", "1", "ip", "1.1.1.1", 8, "5m", "High", "High", "x", "spray"),
            new DetectorSignal("username_enumeration", "1", "ip", "1.1.1.1", 8, "5m", "Medium", "Moderate", "y", "enum"),
            new DetectorSignal("credential_stuffing_pattern", "1", "ip", "1.1.1.1", 8, "5m", "Low", "Moderate", "z", "stuff")
        };

        var result = RiskEvaluator.Evaluate(signals, SourceTrust.Verified, ExceptionClass.None);
        Assert.Contains("password_spray", result.SignalIds);
        Assert.DoesNotContain("username_enumeration", result.SignalIds);
        Assert.DoesNotContain("credential_stuffing_pattern", result.SignalIds);
    }

    [Fact]
    public void UntrustedSource_CannotRecommendBan()
    {
        var signals = new[]
        {
            new DetectorSignal("single_ip_brute_force", "1", "ip", "1.1.1.1", 10, "5m", "High", "High", "x", "brute")
        };
        var result = RiskEvaluator.Evaluate(signals, SourceTrust.Unknown, ExceptionClass.None);
        Assert.Equal("Alert", result.RecommendedAction);
        Assert.Equal("Low", result.Confidence);
    }

    [Fact]
    public void Distributed_RecommendsReview_NotLock()
    {
        var signals = new[]
        {
            new DetectorSignal("distributed_account_attack", "1", "username", "alice", 5, "60s", "Medium", "High", "x", "dist")
        };
        var result = RiskEvaluator.Evaluate(signals, SourceTrust.Verified, ExceptionClass.None);
        Assert.Equal("ManualReview", result.RecommendedAction);
    }
}
