namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

public sealed record PasswordDelayCounter(string Address, int Failures, int NextDelaySeconds);

/// <summary>
/// In-memory failure counts used only to pace password sign-in.
/// </summary>
public sealed class PasswordDelayTracker
{
    private readonly BoundedMap<AttemptWindow> _windows;

    public PasswordDelayTracker(int capacity)
    {
        _windows = new BoundedMap<AttemptWindow>(capacity);
    }

    public int Count(string address, TimeSpan window, DateTimeOffset now)
    {
        return _windows.TryGetValue(address, out var existing) ? existing.Count(now) : 0;
    }

    public void RecordFailure(string address, TimeSpan window, DateTimeOffset now)
    {
        _windows.GetOrAdd(address, _ => new AttemptWindow(window)).Record(now);
    }

    public void Clear(string address)
    {
        if (_windows.TryGetValue(address, out var existing))
        {
            existing.Clear();
        }
    }

    public IReadOnlyList<(string Address, int Failures)> Active(DateTimeOffset now)
    {
        var rows = new List<(string, int)>();
        foreach (var entry in _windows.Snapshot())
        {
            var count = entry.Value.Count(now);
            if (count > 0)
            {
                rows.Add((entry.Key, count));
            }
        }

        return rows;
    }
}
