namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed record DetectorSignal(
    string DetectorId,
    string RuleVersion,
    string SubjectScope,
    string Subject,
    int Observations,
    string TimeWindow,
    string Confidence,
    string Severity,
    string ExplanationCode,
    string Explanation);
