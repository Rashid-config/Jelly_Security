namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed class PolicyAuditEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;

    public string Action { get; set; } = string.Empty;

    public string Target { get; set; } = string.Empty;

    public string Detail { get; set; } = string.Empty;
}
