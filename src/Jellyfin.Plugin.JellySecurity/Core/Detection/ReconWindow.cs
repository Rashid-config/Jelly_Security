namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Sliding-window state for one address on the API recon surface.
/// Tracks failed (4xx) responses, unauthenticated request volume, and how many
/// distinct paths were probed. The dominant signal is failures: a legitimate
/// client carries a valid token and gets 2xx, while a scanner without one
/// collects 401/403/404. Breadth (distinct paths) separates enumeration from a
/// misbehaving client that retries one endpoint.
/// </summary>
public sealed class ReconWindow
{
    /// <summary>Cap on distinct tracked paths — beyond this the count is already conclusive.</summary>
    private const int MaxTrackedPaths = 48;

    private readonly Queue<Hit> _hits = new();
    private readonly HashSet<string> _paths = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private int _failed;
    private int _unauth;
    private bool _reported;

    private readonly record struct Hit(DateTimeOffset At, bool Failed, bool Unauth);

    /// <summary>When the rate-limit response for this address ends. Null when not limited.</summary>
    public DateTimeOffset? LimitedUntilUtc { get; private set; }

    /// <summary>Sets the rate-limit expiry for this address.</summary>
    public void LimitUntil(DateTimeOffset until)
    {
        lock (_gate)
        {
            LimitedUntilUtc = until;
        }
    }

    /// <summary>True while a rate-limit response applies to this address.</summary>
    public bool IsLimited(DateTimeOffset now)
    {
        lock (_gate)
        {
            return LimitedUntilUtc > now;
        }
    }

    /// <summary>Ends an active rate-limit early. Used by the dashboard lift action.</summary>
    /// <returns>True when a limit was active and got cleared.</returns>
    public bool ClearLimit(DateTimeOffset now)
    {
        lock (_gate)
        {
            var was = LimitedUntilUtc > now;
            LimitedUntilUtc = null;
            return was;
        }
    }

    /// <summary>
    /// Records one API-surface request and returns the current assessment.
    /// <paramref name="hasToken"/> is a cheap check for the presence of any
    /// auth token (Authorization Token=, X-Emby-Token, api_key) — it does not
    /// validate the token, so requests carrying a bad token still count as
    /// failures when Jellyfin rejects them.
    /// </summary>
    public ReconAssessment Record(string path, bool hasToken, int statusCode, DateTimeOffset now, TimeSpan window)
    {
        var failed = statusCode is >= 400 and < 500;
        lock (_gate)
        {
            Prune(now, window);
            _hits.Enqueue(new Hit(now, failed, !hasToken));
            if (failed)
            {
                _failed++;
            }

            if (!hasToken)
            {
                _unauth++;
            }

            if (_paths.Count < MaxTrackedPaths)
            {
                _paths.Add(path);
            }

            return new ReconAssessment(_failed, _unauth, _paths.Count);
        }
    }

    /// <summary>
    /// Marks whether a crossing has already produced an event, so a flood
    /// produces one event per episode instead of one per request. The flag
    /// resets when counters fall back below the threshold on prune.
    /// </summary>
    public bool TakeReportFlag()
    {
        lock (_gate)
        {
            if (_reported)
            {
                return false;
            }

            _reported = true;
            return true;
        }
    }

    private void Prune(DateTimeOffset now, TimeSpan window)
    {
        var cutoff = now - window;
        while (_hits.Count > 0 && _hits.Peek().At < cutoff)
        {
            var stale = _hits.Dequeue();
            if (stale.Failed)
            {
                _failed--;
            }

            if (stale.Unauth)
            {
                _unauth--;
            }
        }

        // The path set is bounded and approximates "paths in window"; when
        // everything pruned out, start counting breadth fresh.
        if (_hits.Count == 0)
        {
            _paths.Clear();
            _reported = false;
        }
    }
}

/// <summary>Counts for one address inside the sliding window.</summary>
public readonly record struct ReconAssessment(int Failed, int Unauth, int DistinctPaths);
