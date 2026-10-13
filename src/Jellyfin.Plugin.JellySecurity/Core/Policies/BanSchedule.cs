using Jellyfin.Plugin.JellySecurity.Configuration;

namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

public static class BanSchedule
{
    public static IReadOnlyList<int> ParseMinutes(PluginConfiguration config)
    {
        var values = new List<int>();
        foreach (var part in (config.ProgressiveBanMinutes ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, out var minutes) && minutes > 0)
            {
                values.Add(minutes);
            }
        }

        if (values.Count == 0)
        {
            values.Add(Math.Max(1, config.FirstBanMinutes));
            values.Add(15);
            values.Add(60);
            values.Add(1440);
        }

        return values;
    }

    public static int DurationMinutes(PluginConfiguration config, int strike)
    {
        var ladder = ParseMinutes(config);
        var index = Math.Clamp(strike - 1, 0, ladder.Count - 1);
        return ladder[index];
    }

    /// <summary>
    /// After a quiet period the ladder fades instead of growing forever.
    /// </summary>
    public static int NextStrike(StrikeState state, PluginConfiguration config, DateTimeOffset now)
    {
        lock (state)
        {
            var quiet = TimeSpan.FromDays(Math.Max(1, config.EscalationResetDays));
            if (state.Count > 0 && now - state.LastUtc >= quiet)
            {
                state.Count = 0;
            }

            state.Count++;
            state.LastUtc = now;
            return state.Count;
        }
    }
}
