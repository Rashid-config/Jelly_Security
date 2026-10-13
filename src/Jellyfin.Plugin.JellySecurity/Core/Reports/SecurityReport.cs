using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Reports;

public sealed record SecurityReport(
    int Hours,
    int Events,
    int Failed,
    int Succeeded,
    int Blocked,
    int Incidents,
    int ActiveBans,
    double AverageRiskScore,
    IReadOnlyList<string> TopSignals,
    IReadOnlyList<string> DataQuality);

public static class SecurityReportBuilder
{
    public static SecurityReport Build(
        IReadOnlyList<SecurityEvent> events,
        IReadOnlyList<SecurityIncident> incidents,
        IReadOnlyCollection<BanRecord> bans,
        int hours,
        DateTimeOffset now,
        int geoHits,
        int geoLookups)
    {
        var bounded = Math.Clamp(hours, 1, 8760);
        var since = now.AddHours(-bounded);
        var slice = events.Where(e => e.TimestampUtc >= since).ToArray();
        var scores = slice.Select(e => e.RiskScore).Where(s => s is > 0).Select(s => s!.Value).ToArray();
        var quality = new List<string>
        {
            "Counts come from plugin events, not from Jellyfin activity logs.",
            "Unknown outcomes are HTTP statuses other than 2xx, 401, 403, and 429.",
            "Risk scores are local display values and are not a calibrated standard.",
            "Geography is enrichment only and never raises a ban by itself."
        };

        if (geoLookups > 0)
        {
            quality.Add($"Local geo file matched {geoHits} of {geoLookups} looked-up addresses since this process started.");
        }
        else
        {
            quality.Add("No local geo file is loaded.");
        }

        var top = slice
            .Select(e => e.RecommendedAction)
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .GroupBy(a => a!)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .Select(g => $"{g.Key}:{g.Count()}")
            .ToArray();

        return new SecurityReport(
            bounded,
            slice.Length,
            slice.Count(e => e.Outcome == "Failed"),
            slice.Count(e => e.Outcome == "Succeeded"),
            slice.Count(e => e.Outcome == "Blocked"),
            incidents.Count(i => i.LastUtc >= since),
            bans.Count(b => b.IsActive(now)),
            scores.Length == 0 ? 0 : Math.Round(scores.Average(), 1),
            top,
            quality);
    }
}
