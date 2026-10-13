namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

/// <summary>
/// Distinct keys inside a sliding window.
/// </summary>
public sealed class TimedSet
{
    private readonly Dictionary<string, DateTimeOffset> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public int Add(string key, DateTimeOffset now, TimeSpan window)
    {
        lock (_gate)
        {
            Prune(now, window);
            _items[key] = now;
            return _items.Count;
        }
    }

    public int Count(DateTimeOffset now, TimeSpan window)
    {
        lock (_gate)
        {
            Prune(now, window);
            return _items.Count;
        }
    }

    private void Prune(DateTimeOffset now, TimeSpan window)
    {
        var cutoff = now - window;
        var stale = _items.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray();
        foreach (var key in stale)
        {
            _items.Remove(key);
        }
    }
}
