using Jellyfin.Plugin.JellySecurity.Configuration;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public static class AlertAggregator
{
    public static SecurityIncident? Record(
        IList<SecurityIncident> open,
        DetectorSignal primary,
        RiskAssessment assessment,
        PluginConfiguration config,
        DateTimeOffset now)
    {
        if (assessment.RecommendedAction == "Observe" && assessment.RiskBand == "Low")
        {
            return null;
        }

        var cooldown = TimeSpan.FromMinutes(Math.Max(1, config.AlertCooldownMinutes));
        var existing = open.FirstOrDefault(i =>
            i.DetectorId.Equals(primary.DetectorId, StringComparison.OrdinalIgnoreCase)
            && i.Subject.Equals(primary.Subject, StringComparison.OrdinalIgnoreCase)
            && now < i.CooldownUntilUtc);

        if (existing is not null)
        {
            existing.Count++;
            existing.LastUtc = now;
            existing.RiskBand = assessment.RiskBand;
            existing.RecommendedAction = assessment.RecommendedAction;
            existing.Explanation = assessment.Explanation;
            existing.CooldownUntilUtc = now + cooldown;
            return existing;
        }

        var incident = new SecurityIncident
        {
            DetectorId = primary.DetectorId,
            Subject = primary.Subject,
            RiskBand = assessment.RiskBand,
            RecommendedAction = assessment.RecommendedAction,
            Explanation = assessment.Explanation,
            FirstUtc = now,
            LastUtc = now,
            CooldownUntilUtc = now + cooldown,
            Count = 1
        };
        open.Add(incident);
        return incident;
    }
}
