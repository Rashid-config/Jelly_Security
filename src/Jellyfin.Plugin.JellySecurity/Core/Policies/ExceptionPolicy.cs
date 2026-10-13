using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

/// <summary>
/// Three exception classes plus loopback. Priority is documented and must match the UI.
/// </summary>
public static class ExceptionPolicy
{
    public static ExceptionClass Classify(string? address, PluginConfiguration config)
    {
        if (IpNormalizer.IsLoopback(address))
        {
            return ExceptionClass.Loopback;
        }

        if (CidrMatcher.Matches(address, config.AdminNetworks))
        {
            return ExceptionClass.Administrative;
        }

        if (CidrMatcher.Matches(address, config.MonitoringNetworks))
        {
            return ExceptionClass.Monitoring;
        }

        if (CidrMatcher.Matches(address, config.TrustedNetworks))
        {
            return ExceptionClass.Trusted;
        }

        return ExceptionClass.None;
    }

    /// <summary>
    /// Automatic IP bans never apply to an exception class.
    /// </summary>
    public static bool AllowsAutomaticBan(ExceptionClass exception)
    {
        return exception == ExceptionClass.None;
    }

    /// <summary>
    /// Manual and CIDR bans apply to Trusted and ordinary addresses.
    /// They do not apply to Administrative or Monitoring addresses, so an admin cannot lock themselves out by accident.
    /// Loopback follows the same rule as Trusted: an explicit manual ban is honored.
    /// </summary>
    public static bool AllowsManualBan(ExceptionClass exception)
    {
        return exception is ExceptionClass.None or ExceptionClass.Trusted or ExceptionClass.Loopback;
    }
}
