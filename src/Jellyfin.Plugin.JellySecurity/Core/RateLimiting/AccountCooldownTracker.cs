namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

public sealed record AccountCooldown(string Username, DateTimeOffset UntilUtc, int DistinctIps, string Reason);

public sealed record AccountCooldownView(string Username, DateTimeOffset UntilUtc, int RemainingSeconds, int DistinctIps, string Reason);

/// <summary>
/// Counts a distributed spray against one username and keeps a short pause that is not extended while it is active.
/// </summary>
public sealed class AccountCooldownTracker
{
    private readonly BoundedMap<TimedSet> _ips;
    private readonly BoundedMap<AttemptWindow> _failures;
    private readonly Dictionary<string, AccountCooldown> _active = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public AccountCooldownTracker(int capacity)
    {
        _ips = new BoundedMap<TimedSet>(capacity);
        _failures = new BoundedMap<AttemptWindow>(capacity);
    }

    public (int DistinctIps, int Failures) RecordFailure(string username, string address, TimeSpan window, DateTimeOffset now)
    {
        var ips = _ips.GetOrAdd(username, _ => new TimedSet()).Add(address, now, window);
        var failures = _failures.GetOrAdd(username, _ => new AttemptWindow(window)).Record(now);
        return (ips, failures);
    }

    public AccountCooldown? Active(string username, DateTimeOffset now)
    {
        lock (_gate)
        {
            Prune(now);
            return _active.TryGetValue(username, out var cooldown) ? cooldown : null;
        }
    }

    public bool TryBegin(string username, DateTimeOffset now, DateTimeOffset until, int distinctIps, string reason)
    {
        lock (_gate)
        {
            Prune(now);
            if (_active.TryGetValue(username, out var existing) && existing.UntilUtc > now)
            {
                return false;
            }

            _active[username] = new AccountCooldown(username, until, distinctIps, reason);
            return true;
        }
    }

    public bool Clear(string username)
    {
        lock (_gate)
        {
            return _active.Remove(username);
        }
    }

    public IReadOnlyList<AccountCooldown> Snapshot(DateTimeOffset now)
    {
        lock (_gate)
        {
            Prune(now);
            return _active.Values.OrderBy(item => item.UntilUtc).ToArray();
        }
    }

    private void Prune(DateTimeOffset now)
    {
        var stale = _active.Where(pair => pair.Value.UntilUtc <= now).Select(pair => pair.Key).ToArray();
        foreach (var key in stale)
        {
            _active.Remove(key);
        }
    }
}
