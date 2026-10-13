using Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed class HistoricalRisk
{
    private readonly BoundedMap<RiskPoint> _points = new(10000);

    public int Remember(string? key, int score, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return 0;
        }

        var point = _points.GetOrAdd(key, _ => new RiskPoint());
        lock (point.Gate)
        {
            var decayed = RiskScore.Decay(point.Score, point.LastUtc, now);
            point.Score = Math.Max(decayed, score);
            point.LastUtc = now;
            return point.Score;
        }
    }

    public int Peek(string? key, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(key) || !_points.TryGetValue(key, out var point))
        {
            return 0;
        }

        lock (point.Gate)
        {
            return RiskScore.Decay(point.Score, point.LastUtc, now);
        }
    }

    private sealed class RiskPoint
    {
        public object Gate { get; } = new();

        public int Score { get; set; }

        public DateTimeOffset LastUtc { get; set; }
    }
}
