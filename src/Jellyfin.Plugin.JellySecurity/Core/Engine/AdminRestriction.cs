using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

/// <summary>
/// Conservative admin-network gate. Fail open when identity is untrusted or networks are empty.
/// </summary>
public static class AdminRestriction
{
    public static BanDecision Evaluate(PluginConfiguration config, ClientIdentity identity)
    {
        if (!config.RestrictAdminNetworks || config.Mode == ProtectionMode.Emergency)
        {
            return BanDecision.Allow("Admin network restriction is off.");
        }

        if (CidrMatcher.Split(config.AdminNetworks).Count == 0)
        {
            return BanDecision.Allow("Admin Networks are empty; restriction is ignored to prevent lockout.");
        }

        if (identity.Trust != SourceTrust.Verified || identity.Address is null)
        {
            return BanDecision.Allow("Client address is not verified; admin restriction fails open.");
        }

        var exception = ExceptionPolicy.Classify(identity.Address, config);
        if (exception is ExceptionClass.Administrative or ExceptionClass.Loopback)
        {
            return BanDecision.Allow("Address is an administrative or loopback source.");
        }

        return BanDecision.Deny(
            new BanRecord
            {
                Target = identity.Address,
                Kind = BanKind.Manual,
                Reason = "Admin mutation from outside Admin Networks (partial path map).",
                CreatedBy = "admin-restriction"
            },
            "This mapped admin route is outside the configured Admin Networks. The map does not cover every admin API.");
    }
}
