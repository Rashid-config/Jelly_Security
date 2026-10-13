using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Detectors emit structured signals only. They never create a ban.
/// </summary>
public static class ThreatDetectors
{
    public const string RuleVersion = "1.1.0";

    public static IReadOnlyList<DetectorSignal> Evaluate(ObservationContext context, PluginConfiguration config)
    {
        var signals = new List<DetectorSignal>();
        if (context.Outcome is not ("Failed" or "Blocked"))
        {
            return signals;
        }

        if (config.EnableBruteForceDetector && context.FailuresFromAddress >= Math.Max(3, config.FailuresBeforeBan / 2))
        {
            signals.Add(new DetectorSignal(
                "single_ip_brute_force",
                RuleVersion,
                "ip",
                context.Identity.Address ?? "unknown",
                context.FailuresFromAddress,
                $"{config.FailureWindowMinutes}m",
                context.Identity.Trust == SourceTrust.Verified ? "High" : "Low",
                context.FailuresFromAddress >= config.FailuresBeforeBan ? "High" : "Moderate",
                "brute_force_window",
                $"Repeated failures from one address: {context.FailuresFromAddress}."));
        }

        if (config.EnableDistributedDetector
            && !string.IsNullOrWhiteSpace(context.Username)
            && context.DistinctIpsForUsername >= Math.Max(2, config.DistributedIpCount))
        {
            signals.Add(new DetectorSignal(
                "distributed_account_attack",
                RuleVersion,
                "username",
                SubjectUser(context.Username, config),
                context.DistinctIpsForUsername,
                $"{config.DistributedWindowSeconds}s",
                "Medium",
                "High",
                "distributed_sources",
                $"The same username was tried from {context.DistinctIpsForUsername} addresses. This is an alert, not an account lock."));
        }

        var nameDiversity = context.DistinctUsernamesFromAddress >= Math.Max(2, config.PasswordSprayNames);
        if (config.EnablePasswordSprayDetector && nameDiversity)
        {
            signals.Add(new DetectorSignal(
                "password_spray",
                RuleVersion,
                "ip",
                context.Identity.Address ?? "unknown",
                context.DistinctUsernamesFromAddress,
                $"{config.PasswordSprayWindowMinutes}m",
                context.Identity.Trust == SourceTrust.Verified ? "High" : "Low",
                "High",
                "many_usernames_one_source",
                $"Password-spray pattern: {context.DistinctUsernamesFromAddress} usernames from one address."));
        }

        if (config.EnableEnumerationDetector
            && context.DistinctUsernamesFromAddress >= Math.Max(3, config.PasswordSprayNames / 2))
        {
            signals.Add(new DetectorSignal(
                "username_enumeration",
                RuleVersion,
                "ip",
                context.Identity.Address ?? "unknown",
                context.DistinctUsernamesFromAddress,
                $"{config.PasswordSprayWindowMinutes}m",
                "Medium",
                "Moderate",
                "name_probing",
                "Many distinct usernames from one source. The plugin does not confirm whether a name exists."));
        }

        if ((nameDiversity || context.FailuresFromAddress >= config.FailuresBeforeBan)
            && context.FailuresFromAddress >= 5)
        {
            signals.Add(new DetectorSignal(
                "credential_stuffing_pattern",
                RuleVersion,
                "ip",
                context.Identity.Address ?? "unknown",
                context.FailuresFromAddress,
                $"{config.FailureWindowMinutes}m",
                "Low",
                "Moderate",
                "automated_trial_pattern",
                "Possible credential-stuffing pattern. The plugin never sees passwords, so this is a behavioral guess."));
        }

        if (config.EnableHoneypotDetector && IsHoneypot(context.Username, config))
        {
            var distributedDecoy = context.DistinctIpsForUsername >= 3;
            signals.Add(new DetectorSignal(
                "honeypot_username",
                RuleVersion,
                "ip",
                context.Identity.Address ?? "unknown",
                1,
                "event",
                distributedDecoy ? "Low" : "High",
                distributedDecoy ? "Moderate" : "High",
                "decoy_username",
                distributedDecoy
                    ? "Decoy username used from several addresses. Wide automatic bans stay off."
                    : "Decoy username used. Instant ban runs only when that option is on and the name matches no Jellyfin user."));
        }

        if (config.EnableAdminTargetDetector && IsListedAdmin(context.Username, config))
        {
            signals.Add(new DetectorSignal(
                "administrative_account_targeting",
                RuleVersion,
                "username",
                SubjectUser(context.Username, config),
                context.DistinctIpsForUsername,
                "event",
                "High",
                "High",
                "admin_username_listed",
                "A username from the administrator list was targeted. Sensitivity is higher; the account is not locked."));
        }

        return signals;
    }

    public static string SubjectUser(string? username, PluginConfiguration config)
    {
        return IsHoneypot(username, config) ? "(honeypot)" : username ?? "unknown";
    }

    public static bool IsHoneypot(string? username, PluginConfiguration config)
    {
        return !string.IsNullOrWhiteSpace(config.HoneypotUsername)
            && !string.IsNullOrWhiteSpace(username)
            && string.Equals(username, config.HoneypotUsername.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsListedAdmin(string? username, PluginConfiguration config)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        return CidrMatcher.Split(config.AdministrativeUsernames)
            .Any(name => name.Equals(username, StringComparison.OrdinalIgnoreCase));
    }
}
