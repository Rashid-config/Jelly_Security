using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Sessions;

public readonly record struct AddressUpdate(bool Changed, bool Alert);

public readonly record struct SessionWatchRow(
    string Username,
    string DeviceName,
    string Address,
    bool Playing,
    string Title,
    string Reason);

public sealed record SessionWatchReport(IReadOnlyList<SessionWatchRow> Sessions, int UsersOverLimit, int NewAddresses);

public readonly record struct SessionCloseResult(bool Ok, int Closed, int SparedPlayback, string Message);

/// <summary>
/// Decides when a sign-in looks unfamiliar and which devices are not the current playback.
/// </summary>
public static class SessionWatchPolicy
{
    public const string NewAddress = "NewAddress";
    public const string ManySessions = "ManySessions";
    public const string Both = "Both";

    public static int ConcurrentLimit(int configured)
    {
        var value = configured <= 0 ? 4 : configured;
        return Math.Clamp(value, 2, 50);
    }

    public static int CooldownMinutes(int configured)
    {
        var value = configured <= 0 ? 60 : configured;
        return Math.Clamp(value, 1, 1440);
    }

    public static bool TooMany(int sessions, int configured)
    {
        return sessions >= ConcurrentLimit(configured);
    }

    public static string? NormalizeEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return null;
        }

        var text = endpoint.Trim();
        if (text.StartsWith('['))
        {
            var end = text.IndexOf(']');
            if (end > 1)
            {
                return IpNormalizer.Normalize(text[1..end]);
            }
        }

        if (text.Count(ch => ch == ':') == 1)
        {
            var host = IpNormalizer.Normalize(text[..text.LastIndexOf(':')]);
            if (host is not null)
            {
                return host;
            }
        }

        return IpNormalizer.Normalize(text);
    }

    public static IReadOnlyList<string> DevicesToClose(IEnumerable<string?> deviceIds, IEnumerable<string?> playingDeviceIds)
    {
        var playing = playingDeviceIds.ToArray();
        if (playing.Any(string.IsNullOrWhiteSpace))
        {
            return [];
        }

        var spare = new HashSet<string>(playing.Where(id => !string.IsNullOrWhiteSpace(id))!, StringComparer.OrdinalIgnoreCase);
        return deviceIds
            .Where(id => !string.IsNullOrWhiteSpace(id) && !spare.Contains(id!))
            .Select(id => id!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

/// <summary>
/// Addresses already seen for each account. The first address is remembered quietly.
/// </summary>
public sealed class KnownAddressBook
{
    private readonly Dictionary<string, List<string>> _map = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public AddressUpdate Note(string username, string address, int maxPerUser = 32)
    {
        var name = username.Trim();
        var ip = address.Trim();
        if (name.Length == 0 || ip.Length == 0)
        {
            return new AddressUpdate(false, false);
        }

        lock (_gate)
        {
            if (!_map.TryGetValue(name, out var list))
            {
                list = [];
                _map[name] = list;
            }

            if (list.Exists(item => item.Equals(ip, StringComparison.OrdinalIgnoreCase)))
            {
                return new AddressUpdate(false, false);
            }

            var alert = list.Count > 0;
            list.Add(ip);
            var cap = Math.Clamp(maxPerUser, 1, 64);
            while (list.Count > cap)
            {
                list.RemoveAt(0);
            }

            while (_map.Count > 2000)
            {
                var extra = _map.Keys.FirstOrDefault(key => !key.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (extra is null)
                {
                    break;
                }

                _map.Remove(extra);
            }

            return new AddressUpdate(true, alert);
        }
    }

    public bool HasHistory(string username)
    {
        lock (_gate)
        {
            return _map.TryGetValue(username.Trim(), out var list) && list.Count > 0;
        }
    }

    public bool Contains(string username, string address)
    {
        lock (_gate)
        {
            return _map.TryGetValue(username.Trim(), out var list)
                && list.Exists(item => item.Equals(address.Trim(), StringComparison.OrdinalIgnoreCase));
        }
    }

    public void Import(IReadOnlyDictionary<string, List<string>>? saved)
    {
        if (saved is null)
        {
            return;
        }

        lock (_gate)
        {
            foreach (var pair in saved)
            {
                if (string.IsNullOrWhiteSpace(pair.Key) || pair.Value is null)
                {
                    continue;
                }

                var list = pair.Value
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Select(item => item.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(64)
                    .ToList();
                if (list.Count > 0)
                {
                    _map[pair.Key.Trim()] = list;
                }
            }
        }
    }

    public Dictionary<string, List<string>> Export()
    {
        lock (_gate)
        {
            return _map.ToDictionary(pair => pair.Key, pair => pair.Value.ToList(), StringComparer.OrdinalIgnoreCase);
        }
    }
}
