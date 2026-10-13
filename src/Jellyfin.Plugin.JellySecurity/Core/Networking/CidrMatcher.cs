using System.Net;

namespace Jellyfin.Plugin.JellySecurity.Core.Networking;

/// <summary>
/// Matches a single address against IP or CIDR entries.
/// </summary>
public static class CidrMatcher
{
    public static bool Matches(string? ip, string? list)
    {
        var normalized = IpNormalizer.Normalize(ip);
        if (normalized is null || !IPAddress.TryParse(normalized, out var address))
        {
            return false;
        }

        foreach (var entry in Split(list))
        {
            if (IPAddress.TryParse(entry, out var single) && single.Equals(address))
            {
                return true;
            }

            if (IPNetwork.TryParse(entry, out var network) && network.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    public static IReadOnlyList<string> Split(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return value
            .Split([',', ';', '\r', '\n', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();
    }
}
