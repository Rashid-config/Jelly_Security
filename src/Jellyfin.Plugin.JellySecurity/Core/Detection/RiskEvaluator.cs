using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Combines independent signals. Does not add the same evidence twice.
/// </summary>
public static class RiskEvaluator
{
    public static RiskAssessment Evaluate(
        IReadOnlyList<DetectorSignal> signals,
        SourceTrust trust,
        ExceptionClass exception)
    {
        if (signals.Count == 0)
        {
            return new RiskAssessment("Low", "Low", "Observe", "ObserveOnly", [], "No threat detector fired.");
        }

        var ids = new List<string>();
        var sawNameDiversity = false;
        foreach (var signal in signals)
        {
            if (signal.DetectorId is "password_spray" or "username_enumeration" or "credential_stuffing_pattern")
            {
                if (sawNameDiversity && signal.DetectorId != "password_spray")
                {
                    continue;
                }

                sawNameDiversity = true;
            }

            if (!ids.Contains(signal.DetectorId, StringComparer.Ordinal))
            {
                ids.Add(signal.DetectorId);
            }
        }

        var band = "Moderate";
        if (ids.Contains("honeypot_username") || ids.Contains("distributed_account_attack") || ids.Contains("administrative_account_targeting"))
        {
            band = "High";
        }

        if (ids.Contains("honeypot_username") && ids.Contains("administrative_account_targeting"))
        {
            band = "Critical";
        }

        var confidence = trust == SourceTrust.Verified ? "High" : "Low";
        if (trust != SourceTrust.Verified && band is "High" or "Critical")
        {
            band = "Moderate";
        }

        var action = "Alert";
        if (ids.Contains("distributed_account_attack") || ids.Contains("administrative_account_targeting"))
        {
            action = "ManualReview";
        }
        else if (ids.Contains("single_ip_brute_force") && trust == SourceTrust.Verified && exception == ExceptionClass.None)
        {
            action = "TemporarySourceBan";
        }
        else if (ids.Contains("password_spray") && trust == SourceTrust.Verified)
        {
            action = "Throttle";
        }

        if (trust != SourceTrust.Verified || exception != ExceptionClass.None)
        {
            if (action is "TemporarySourceBan" or "Throttle")
            {
                action = "Alert";
            }

            confidence = "Low";
        }

        var decision = action switch
        {
            "TemporarySourceBan" => "Recommended only; automatic ban still requires the enablement gate.",
            "Throttle" => "Recommended throttle; no thread sleep is applied.",
            "ManualReview" => "Alert for the administrator. The account is not locked.",
            _ => "Observe or alert. No automatic account action."
        };

        var explanation = string.Join(" ", signals.Select(s => s.Explanation).Distinct());
        return new RiskAssessment(band, confidence, action, decision, ids, explanation);
    }
}
