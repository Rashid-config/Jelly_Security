using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Jellyfin.Plugin.JellySecurity.Integration;

namespace Jellyfin.Plugin.JellySecurity.Core.RateLimiting;

public readonly record struct LoginDelayDecision(TimeSpan Delay, int PriorFailures, string Reason)
{
    public static LoginDelayDecision Off(string reason) => new(TimeSpan.Zero, 0, reason);
}

/// <summary>
/// Short, capped pauses for repeated password sign-in attempts.
/// Playback and other routes are outside this policy.
/// </summary>
public static class LoginDelayPolicy
{
    /// <summary>
    /// Absolute ceiling for a single delay. Capped at 10 seconds to limit
    /// slow-loris exposure: an attacker opening many connections and holding
    /// each for the maximum delay consumes sockets for a short, bounded time.
    /// </summary>
    public const int AbsoluteCeilingSeconds = 10;

    public static bool Applies(PluginConfiguration config, AuthPathKind kind, ClientIdentity identity, ExceptionClass exception)
    {
        if (!config.PasswordDelayEnabled || kind != AuthPathKind.Password || identity.Address is null)
        {
            return false;
        }

        if (config.PasswordDelayRequireVerifiedAddress && identity.Trust != SourceTrust.Verified)
        {
            return false;
        }

        return !config.PasswordDelaySkipPrivilegedNetworks || exception == ExceptionClass.None;
    }

    public static LoginDelayDecision Evaluate(PluginConfiguration config, int priorFailures)
    {
        if (!config.PasswordDelayEnabled)
        {
            return LoginDelayDecision.Off("Password delay is off.");
        }

        var threshold = Threshold(config);
        if (priorFailures < threshold)
        {
            return new LoginDelayDecision(TimeSpan.Zero, priorFailures, "The failure count is still under the delay threshold.");
        }

        var ceiling = CeilingSeconds(config);
        var steps = ParseSteps(config.PasswordDelayStepsSeconds, ceiling);
        var index = priorFailures - threshold;
        if (index >= steps.Length)
        {
            index = steps.Length - 1;
        }

        var seconds = Math.Min(steps[index], ceiling);
        return new LoginDelayDecision(TimeSpan.FromSeconds(seconds), priorFailures, $"Password sign-in waits {seconds}s.");
    }

    public static int CeilingSeconds(PluginConfiguration config)
    {
        var requested = config.PasswordDelayCeilingSeconds <= 0 ? 5 : config.PasswordDelayCeilingSeconds;
        return Math.Clamp(requested, 1, AbsoluteCeilingSeconds);
    }

    public static TimeSpan Window(PluginConfiguration config)
    {
        var minutes = config.PasswordDelayWindowMinutes <= 0 ? 15 : config.PasswordDelayWindowMinutes;
        return TimeSpan.FromMinutes(Math.Clamp(minutes, 1, 1440));
    }

    public static int Threshold(PluginConfiguration config)
    {
        var value = config.PasswordDelayAfterFailures < 1 ? 1 : config.PasswordDelayAfterFailures;
        return Math.Min(value, 100);
    }

    public static int[] ParseSteps(string? text, int ceiling)
    {
        var parsed = new List<int>();
        if (!string.IsNullOrWhiteSpace(text))
        {
            foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (int.TryParse(part, out var seconds) && seconds > 0)
                {
                    parsed.Add(Math.Min(seconds, ceiling));
                }
            }
        }

        if (parsed.Count == 0)
        {
            parsed.Add(Math.Min(1, ceiling));
            parsed.Add(Math.Min(3, ceiling));
            parsed.Add(Math.Min(5, ceiling));
        }

        return parsed.ToArray();
    }
}
