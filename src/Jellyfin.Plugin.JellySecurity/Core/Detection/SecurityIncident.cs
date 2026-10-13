namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed class SecurityIncident
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string DetectorId { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public string RiskBand { get; set; } = "Low";

    public string RecommendedAction { get; set; } = "Observe";

    public string Explanation { get; set; } = string.Empty;

    public int Count { get; set; } = 1;

    public DateTimeOffset FirstUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset LastUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset CooldownUntilUtc { get; set; }

    /// <summary>
    /// Returns a defensive copy so callers reading a snapshot cannot race
    /// with the aggregator mutating the live incident in the list.
    /// </summary>
    public SecurityIncident Clone() => new()
    {
        Id = Id,
        DetectorId = DetectorId,
        Subject = Subject,
        RiskBand = RiskBand,
        RecommendedAction = RecommendedAction,
        Explanation = Explanation,
        Count = Count,
        FirstUtc = FirstUtc,
        LastUtc = LastUtc,
        CooldownUntilUtc = CooldownUntilUtc
    };
}
