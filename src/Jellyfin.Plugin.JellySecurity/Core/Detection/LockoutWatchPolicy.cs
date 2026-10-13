namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public readonly record struct LockoutWatchRow(string Username, int Attempts, int Limit, int Remaining, string State);

public sealed record LockoutWatchReport(
    IReadOnlyList<LockoutWatchRow> Watches,
    int AccountsWithoutLockout,
    int AccountsRead,
    bool ReadFailed);

/// <summary>
/// Reads a Jellyfin per-user lockout limit. A non-positive limit means that account is not locked by the counter.
/// </summary>
public static class LockoutWatchPolicy
{
    public const string NotConfigured = "NotConfigured";
    public const string Clear = "Clear";
    public const string Approaching = "Approaching";
    public const string Reached = "Reached";

    public static bool LockoutConfigured(int? limit) => limit is > 0;

    public static int WarnWithin(int configured)
    {
        var value = configured <= 0 ? 5 : configured;
        return Math.Clamp(value, 1, 100);
    }

    public static int CooldownMinutes(int configured)
    {
        var value = configured <= 0 ? 60 : configured;
        return Math.Clamp(value, 1, 1440);
    }

    public static string Classify(int attempts, int? limit, int warnWithin)
    {
        if (limit is not int configured || !LockoutConfigured(configured))
        {
            return NotConfigured;
        }

        if (attempts >= configured)
        {
            return Reached;
        }

        var remaining = configured - attempts;
        return remaining <= WarnWithin(warnWithin) ? Approaching : Clear;
    }

    public static int Remaining(int attempts, int? limit)
    {
        return limit is int configured && LockoutConfigured(configured) ? configured - attempts : 0;
    }
}
