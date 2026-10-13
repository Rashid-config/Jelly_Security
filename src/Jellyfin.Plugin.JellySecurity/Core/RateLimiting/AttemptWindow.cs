namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

/// <summary>
/// Counts events inside a sliding time window.
/// </summary>
public sealed class AttemptWindow
{
    private readonly Queue<DateTimeOffset> _hits = new();
    private readonly TimeSpan _window;
    private readonly object _gate = new();

    public AttemptWindow(TimeSpan window)
    {
        _window = window <= TimeSpan.Zero ? TimeSpan.FromMinutes(5) : window;
    }

    public int Record(DateTimeOffset now)
    {
        lock (_gate)
        {
            Prune(now);
            _hits.Enqueue(now);
            return _hits.Count;
        }
    }

    public int Count(DateTimeOffset now)
    {
        lock (_gate)
        {
            Prune(now);
            return _hits.Count;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _hits.Clear();
        }
    }

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now - _window;
        while (_hits.Count > 0 && _hits.Peek() < cutoff)
        {
            _hits.Dequeue();
        }
    }
}
