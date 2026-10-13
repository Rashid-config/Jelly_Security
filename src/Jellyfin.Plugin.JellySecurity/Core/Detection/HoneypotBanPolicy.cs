using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public readonly record struct HoneypotBanDecision(bool Ban, string Reason);

/// <summary>
/// Instant ban is a separate switch. It stays idle when the decoy name belongs to a real user.
/// </summary>
public static class HoneypotBanPolicy
{
    public static HoneypotBanDecision Evaluate(
        bool instantEnabled,
        bool nameConfigured,
        bool matchesExistingUser,
        bool verifiedAddress,
        bool ipv4,
        ExceptionClass exception)
    {
        if (!instantEnabled || !nameConfigured)
        {
            return new HoneypotBanDecision(false, "Honeypot instant ban is off.");
        }

        if (matchesExistingUser)
        {
            return new HoneypotBanDecision(false, "The honeypot name matches a Jellyfin user, so instant ban stays off.");
        }

        if (!verifiedAddress)
        {
            return new HoneypotBanDecision(false, "The client address is not verified.");
        }

        if (!ipv4)
        {
            return new HoneypotBanDecision(false, "Honeypot instant ban applies to a single IPv4 address.");
        }

        if (!ExceptionPolicy.AllowsAutomaticBan(exception))
        {
            return new HoneypotBanDecision(false, "This network is excluded from automatic bans.");
        }

        return new HoneypotBanDecision(true, "A honeypot name that matches no Jellyfin user was used.");
    }

    public static int DurationMinutes(int configured)
    {
        var minutes = configured <= 0 ? 60 : configured;
        return Math.Clamp(minutes, 1, 1440);
    }
}
