using System.Net;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Geo;

/// <summary>
/// One administrator row in the country block list. Ranges is plain CIDR or address text
/// separated by commas or new lines, kept editable so the list can be adjusted by hand.
/// </summary>
public sealed class GeoBlockRule
{
    public string Name { get; set; } = string.Empty;

    public string Ranges { get; set; } = string.Empty;

    public bool Enabled { get; set; }
}

/// <summary>
/// Matches a sign-in address against the administrator's country block list.
/// Rows are enforced like manual bans: admin and monitoring networks are never blocked,
/// and nothing happens while "Enforce the addresses I block" is off.
/// </summary>
public static class GeoBlockPolicy
{
    /// <summary>Returns the matching row's name when the address falls inside an enabled row, else null.</summary>
    public static string? Match(PluginConfiguration config, string? address)
    {
        if (string.IsNullOrWhiteSpace(address) || config.GeoBlocks.Count == 0)
        {
            return null;
        }

        foreach (var rule in config.GeoBlocks)
        {
            if (!rule.Enabled || string.IsNullOrWhiteSpace(rule.Ranges))
            {
                continue;
            }

            if (CidrMatcher.Matches(address, rule.Ranges))
            {
                return string.IsNullOrWhiteSpace(rule.Name) ? "unnamed" : rule.Name;
            }
        }

        return null;
    }

    /// <summary>Counts the entries in one row that parse as an address or CIDR, for the dashboard preview.</summary>
    public static int CountRanges(GeoBlockRule rule)
    {
        var count = 0;
        foreach (var entry in CidrMatcher.Split(rule.Ranges))
        {
            if (IPAddress.TryParse(entry, out _) || IPNetwork.TryParse(entry, out _))
            {
                count++;
            }
        }

        return count;
    }
}
