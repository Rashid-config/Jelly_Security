using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Geo;

/// <summary>
/// Optional local CSV: address-or-cidr,country,asn. No download, no external lookup.
/// </summary>
public static class LocalGeoDirectory
{
    public static IReadOnlyList<GeoRecord> Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        var records = new List<GeoRecord>();
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var parts = line.Split(',', StringSplitOptions.TrimEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            records.Add(new GeoRecord(parts[0], parts[1], parts.Length > 2 ? parts[2] : string.Empty));
        }

        return records;
    }

    public static GeoRecord? Lookup(string? ip, IReadOnlyList<GeoRecord> records)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return null;
        }

        foreach (var record in records)
        {
            if (CidrMatcher.Matches(ip, record.Network))
            {
                return record;
            }
        }

        return null;
    }
}

public sealed record GeoRecord(string Network, string Country, string Asn);
