namespace Jellyfin.Plugin.JellySecurity.Core.Policies;

public sealed class BanRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string Target { get; set; } = string.Empty;

    public BanKind Kind { get; set; }

    public string Reason { get; set; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? ExpiresUtc { get; set; }

    public int Strike { get; set; }

    public string CreatedBy { get; set; } = "administrator";

    public bool IsActive(DateTimeOffset now)
    {
        return ExpiresUtc is null || ExpiresUtc > now;
    }
}
