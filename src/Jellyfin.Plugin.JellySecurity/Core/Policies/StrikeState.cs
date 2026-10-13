namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

public sealed class StrikeState
{
    public int Count { get; set; }

    public DateTimeOffset LastUtc { get; set; }
}
