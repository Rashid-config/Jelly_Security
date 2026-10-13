using System.Net;
using System.Net.Sockets;

namespace Jellyfin.Plugin.JellySecurity.Core.Networking;

/// <summary>
/// Computes the network prefix for an IPv6 address. Used for automatic /64 prefix bans
/// so a client that rotates addresses inside its assigned subnet is still contained.
/// </summary>
public static class Ipv6Prefix
{
    /// <summary>
    /// Returns the CIDR string for the prefix of the given length containing the address,
    /// or null if the address is not IPv6 or the prefix length is out of range.
    /// </summary>
    public static string? Of(string? ip, int prefixLength)
    {
        if (string.IsNullOrWhiteSpace(ip) || prefixLength < 1 || prefixLength > 128)
        {
            return null;
        }

        var normalized = IpNormalizer.Normalize(ip);
        if (normalized is null || !IPAddress.TryParse(normalized, out var address))
        {
            return null;
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return null;
        }

        var bytes = address.GetAddressBytes();
        var full = prefixLength / 8;
        var partial = prefixLength % 8;

        var prefix = new byte[16];
        if (full > 0)
        {
            Array.Copy(bytes, prefix, full);
        }

        if (partial > 0 && full < 16)
        {
            var mask = (byte)(0xFF << (8 - partial));
            prefix[full] = (byte)(bytes[full] & mask);
        }

        var network = new IPAddress(prefix);
        return $"{network}/{prefixLength}";
    }
}
