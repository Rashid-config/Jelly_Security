using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Jellyfin.Plugin.JellySecurity.Integration;

namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

public readonly record struct AccountCooldownDecision(bool Block, int RemainingSeconds, string Reason)
{
    public static AccountCooldownDecision Allow(string reason) => new(false, 0, reason);
}

/// <summary>
/// A plugin-owned pause for one username. It expires by itself and does not disable the Jellyfin account.
/// </summary>
public static class AccountCooldownPolicy
{
    public static string? NormalizeUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        var text = username.Trim();
        return text.Length <= 128 ? text : text[..128];
    }

    public static bool IsClearSpray(PluginConfiguration config, int distinctIps, int failures)
    {
        return config.AccountCooldownEnabled
            && distinctIps >= DistinctIps(config)
            && failures >= Failures(config);
    }

    public static bool Blocks(
        PluginConfiguration config,
        AuthPathKind kind,
        ClientIdentity identity,
        ExceptionClass exception,
        bool cooldownActive)
    {
        if (!config.AccountCooldownEnabled || !cooldownActive || kind != AuthPathKind.Password)
        {
            return false;
        }

        return !config.AccountCooldownSkipPrivilegedNetworks || exception == ExceptionClass.None;
    }

    public static TimeSpan Duration(PluginConfiguration config)
    {
        var minutes = config.AccountCooldownMinutes <= 0 ? 15 : config.AccountCooldownMinutes;
        return TimeSpan.FromMinutes(Math.Clamp(minutes, 1, 1440));
    }

    public static TimeSpan Window(PluginConfiguration config)
    {
        var minutes = config.AccountCooldownWindowMinutes <= 0 ? 15 : config.AccountCooldownWindowMinutes;
        return TimeSpan.FromMinutes(Math.Clamp(minutes, 1, 1440));
    }

    public static int DistinctIps(PluginConfiguration config)
    {
        var value = config.AccountCooldownDistinctIps <= 0 ? 5 : config.AccountCooldownDistinctIps;
        return Math.Clamp(value, 2, 100);
    }

    public static int Failures(PluginConfiguration config)
    {
        var value = config.AccountCooldownFailures <= 0 ? 8 : config.AccountCooldownFailures;
        return Math.Clamp(value, 2, 100);
    }
}
