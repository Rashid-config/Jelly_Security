using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Edge;

/// <summary>
/// Authenticated, limited edge channel. Disabled until a long shared key is set.
/// External threat lists are never applied automatically.
/// </summary>
public static class EdgeAccess
{
    public static bool IsAuthorized(PluginConfiguration config, string? providedKey, string? peerAddress)
    {
        if (!config.EdgeChannelEnabled)
        {
            return false;
        }

        var expected = config.EdgeSharedKey ?? string.Empty;
        if (expected.Length < 16 || string.IsNullOrEmpty(providedKey))
        {
            return false;
        }

        var left = Encoding.UTF8.GetBytes(providedKey);
        var right = Encoding.UTF8.GetBytes(expected);
        if (left.Length != right.Length || !CryptographicOperations.FixedTimeEquals(left, right))
        {
            return false;
        }

        if (!config.EdgeRestrictToTrustedPeers)
        {
            return true;
        }

        return IpNormalizer.IsLoopback(peerAddress) || CidrMatcher.Matches(peerAddress, config.KnownProxies);
    }
}
