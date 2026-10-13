using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

/// <summary>
/// Two-step enablement: automatic IP bans stay closed until the environment is ready.
/// </summary>
public static class EnablementGate
{
    public static EnvironmentStatus Evaluate(PluginConfiguration config)
    {
        var warnings = new List<string>();
        var proxy = "NotRequired";

        if (config.TrustForwardedFor)
        {
            if (CidrMatcher.Split(config.KnownProxies).Count == 0)
            {
                proxy = "Unknown";
                warnings.Add("X-Forwarded-For is trusted but no Known Proxies are configured. Automatic IP bans stay off.");
            }
            else
            {
                proxy = "Verified";
            }
        }

        if (config.AutomaticIpBans && config.Mode == ProtectionMode.MonitorOnly)
        {
            warnings.Add("Automatic IP bans are ignored while the mode is Monitor Only.");
        }

        if (config.AutomaticIpBans && config.Mode != ProtectionMode.MonitorOnly && proxy == "Unknown")
        {
            warnings.Add("Automatic IP enforcement is requested but the client address cannot be trusted.");
        }

        if (config.Mode == ProtectionMode.Strict)
        {
            warnings.Add("Strict mode: thresholds are tighter. Lower the failure count or window in the settings to match.");
        }

        warnings.Add("A request this plugin rejects does not write Jellyfin's failed-attempt counter, and it is not a substitute for that counter.");

        var automaticReady = config.AutomaticIpBans
            && config.Mode != ProtectionMode.MonitorOnly
            && proxy != "Unknown";

        var state = "MonitorOnly";
        if (config.Mode == ProtectionMode.Emergency)
        {
            state = "Degraded";
        }
        else if (config.Mode != ProtectionMode.MonitorOnly && automaticReady)
        {
            state = config.Mode == ProtectionMode.Strict ? "StrictEnforcement" : "EnforcementActive";
        }
        else if (config.Mode != ProtectionMode.MonitorOnly && config.AutomaticIpBans && proxy == "Unknown")
        {
            state = "Degraded";
        }

        return new EnvironmentStatus(
            state,
            proxy,
            automaticReady,
            PreAuthLockoutProtectionProven: false,
            warnings);
    }
}

public sealed record EnvironmentStatus(
    string EngineState,
    string ProxyStatus,
    bool AutomaticEnforcementReady,
    bool PreAuthLockoutProtectionProven,
    IReadOnlyList<string> Warnings);
