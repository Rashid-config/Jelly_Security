using System.Net;
using System.Net.Sockets;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

public sealed record BanTargetResult(bool Ok, string? Normalized, BanKind Kind, string Message);

/// <summary>
/// Rejects invalid and whole-internet CIDR before a ban is stored.
/// </summary>
public static class BanTargetValidator
{
    public static BanTargetResult Validate(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return new BanTargetResult(false, null, BanKind.Manual, "Target is required.");
        }

        var trimmed = target.Trim();
        if (trimmed.Contains('/', StringComparison.Ordinal))
        {
            if (IsWholeInternet(trimmed))
            {
                return new BanTargetResult(false, null, BanKind.Cidr, "Refusing to ban the entire internet (0.0.0.0/0 or ::/0).");
            }

            if (!IPNetwork.TryParse(trimmed, out var network))
            {
                return new BanTargetResult(false, null, BanKind.Cidr, "CIDR is not valid.");
            }

            if (network.PrefixLength == 0)
            {
                return new BanTargetResult(false, null, BanKind.Cidr, "Prefix length 0 is not allowed.");
            }

            return new BanTargetResult(true, network.ToString(), BanKind.Cidr, "CIDR accepted.");
        }

        var ip = IpNormalizer.Normalize(trimmed);
        if (ip is null)
        {
            return new BanTargetResult(false, null, BanKind.Manual, "Value is not a valid IPv4, IPv6, or CIDR address.");
        }

        return new BanTargetResult(true, ip, BanKind.Manual, "Address accepted.");
    }

    public static bool IsWideIpv6Prefix(string cidr)
    {
        return IPNetwork.TryParse(cidr, out var network)
            && network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6
            && network.PrefixLength < 64;
    }

    private static bool IsWholeInternet(string cidr)
    {
        return cidr.Equals("0.0.0.0/0", StringComparison.Ordinal)
            || cidr.Equals("::/0", StringComparison.OrdinalIgnoreCase);
    }
}
