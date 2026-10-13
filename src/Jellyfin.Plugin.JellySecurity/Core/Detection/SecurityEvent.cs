namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public sealed class SecurityEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;

    public string Kind { get; set; } = string.Empty;

    public string Outcome { get; set; } = string.Empty;

    public string? Username { get; set; }

    public string? Address { get; set; }

    public string Path { get; set; } = string.Empty;

    public string Trust { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;

    public bool Enforced { get; set; }

    public string? RiskBand { get; set; }

    public string? RecommendedAction { get; set; }

    public int? RiskScore { get; set; }

    public string? Country { get; set; }
}
