namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed record RiskAssessment(
    string RiskBand,
    string Confidence,
    string RecommendedAction,
    string PolicyDecision,
    IReadOnlyList<string> SignalIds,
    string Explanation);
