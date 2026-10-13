using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Local 0-100 display score. Weights are starting points, not a calibrated standard.
/// Geography never increases the score.
/// </summary>
public static class RiskScore
{
    public static int FromBand(string band)
    {
        return band switch
        {
            "Critical" => 90,
            "High" => 70,
            "Moderate" => 40,
            _ => 15
        };
    }

    public static int Combine(RiskAssessment assessment, int historical, SourceTrust trust)
    {
        var current = FromBand(assessment.RiskBand);
        if (assessment.Confidence == "Low" || trust != SourceTrust.Verified)
        {
            current = Math.Min(current, 40);
        }

        var blended = (int)Math.Round((current * 0.7) + (historical * 0.3));
        if (assessment.Confidence == "Low" || trust != SourceTrust.Verified)
        {
            blended = Math.Min(blended, 40);
        }

        return Math.Clamp(blended, 0, 100);
    }

    public static int Decay(int score, DateTimeOffset lastUtc, DateTimeOffset now)
    {
        if (score <= 0)
        {
            return 0;
        }

        var hours = Math.Max(0, (now - lastUtc).TotalHours);
        var factor = Math.Pow(0.5, hours / 24.0);
        return (int)Math.Round(score * factor);
    }
}
