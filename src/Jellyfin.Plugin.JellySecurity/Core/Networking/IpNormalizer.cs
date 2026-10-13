using System.Net;
using System.Net.Sockets;

namespace Jellyfin.Plugin.JellySecurity.Core.Networking;

/// <summary>
/// Normalizes client addresses for comparison and storage.
/// </summary>
public static class IpNormalizer
{
    public static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim().Trim('[', ']');
        var zone = trimmed.IndexOf('%', StringComparison.Ordinal);
        if (zone >= 0)
        {
            trimmed = trimmed[..zone];
        }

        if (!IPAddress.TryParse(trimmed, out var address))
        {
            return null;
        }

        return Normalize(address);
    }

    public static string Normalize(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.ToString();
    }

    public static bool IsLoopback(string? ip)
    {
        var normalized = Normalize(ip);
        return normalized is not null
            && IPAddress.TryParse(normalized, out var address)
            && IPAddress.IsLoopback(address);
    }

    public static bool IsIPv6(string? ip)
    {
        return Normalize(ip) is { } normalized
            && IPAddress.TryParse(normalized, out var address)
            && address.AddressFamily == AddressFamily.InterNetworkV6;
    }
}
