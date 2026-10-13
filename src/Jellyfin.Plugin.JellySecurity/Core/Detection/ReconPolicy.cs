using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Threshold and enforcement checks for the API reconnaissance watch. Kept
/// pure/static so the rules can be unit-tested without a SecurityEngine.
/// </summary>
public static class ReconPolicy
{
    /// <summary>
    /// Whether the observed counters cross the detection threshold: either
    /// enough failed (4xx) responses, or heavy unauthenticated breadth across
    /// distinct paths.
    /// </summary>
    public static bool ThresholdCrossed(ReconAssessment assessment, PluginConfiguration config)
    {
        return assessment.Failed >= Math.Max(1, config.ReconFailedThreshold)
            || (assessment.Unauth >= Math.Max(1, config.ReconUnauthThreshold)
                && assessment.DistinctPaths >= Math.Max(1, config.ReconDistinctPathMin));
    }

    /// <summary>
    /// Whether a fresh rate-limit may be applied to this address: enforcement
    /// must be opted in, the source address must be verified, and the address
    /// must not sit on an exception network.
    /// </summary>
    public static bool MayEnforce(PluginConfiguration config, ClientIdentity identity)
    {
        return config.ReconEnforce
            && identity.Address is not null
            && identity.Trust == SourceTrust.Verified
            && ExceptionPolicy.Classify(identity.Address, config) == ExceptionClass.None;
    }

    /// <summary>
    /// Whether the address should be served 429 right now. Returns the
    /// Retry-After seconds through <paramref name="retryAfterSeconds"/>.
    /// </summary>
    public static bool ShouldBlock(PluginConfiguration config, ClientIdentity identity, ReconWindow? window, DateTimeOffset now, out int retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        if (!config.ReconEnforce || window is null || !window.IsLimited(now))
        {
            return false;
        }

        if (identity.Address is null
            || identity.Trust != SourceTrust.Verified
            || ExceptionPolicy.Classify(identity.Address, config) != ExceptionClass.None)
        {
            return false;
        }

        retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((window.LimitedUntilUtc!.Value - now).TotalSeconds));
        return true;
    }
}
