using System.Text.RegularExpressions;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Parsed client identity from the Jellyfin/Emby authorization header.
/// Jellyfin clients send an Authorization or X-Emby-Authorization header in
/// the format: <c>MediaBrowser Client="...", Device="...", DeviceId="...", Version="..."</c>
/// This is stronger evidence of client identity than User-Agent alone because
/// legitimate Jellyfin clients generate a stable DeviceId per installation.
/// A bot that spoofs a TV User-Agent but sends no DeviceId, or sends a
/// malformed one, can be distinguished from a real TV client.
/// </summary>
public sealed class DeviceFingerprint
{
    /// <summary>
    /// The Client field (e.g. "Jellyfin Web", "Jellyfin Android", "Infuse").
    /// </summary>
    public string? Client { get; set; }

    /// <summary>
    /// The Device field (e.g. "Chrome on Windows", "Samsung TV", "iPhone 15").
    /// </summary>
    public string? Device { get; set; }

    /// <summary>
    /// The DeviceId field — a unique identifier generated per installation.
    /// Real Jellyfin clients send a non-empty, stable DeviceId. Bots often
    /// omit it or send a garbage value.
    /// </summary>
    public string? DeviceId { get; set; }

    /// <summary>
    /// The Version field (e.g. "10.8.0", "1.0.0").
    /// </summary>
    public string? Version { get; set; }

    /// <summary>
    /// True if the header was present and parseable (even if some fields are empty).
    /// </summary>
    public bool HasHeader { get; set; }

    /// <summary>
    /// True if a non-empty DeviceId was present. This is the key signal:
    /// legitimate Jellyfin apps always send one; bots usually don't.
    /// </summary>
    public bool HasDeviceId => !string.IsNullOrWhiteSpace(DeviceId);

    /// <summary>
    /// True if a non-empty Client field was present.
    /// </summary>
    public bool HasClient => !string.IsNullOrWhiteSpace(Client);

    /// <summary>
    /// Parses the Authorization or X-Emby-Authorization header.
    /// Returns a fingerprint with <see cref="HasHeader"/> = false if the
    /// header is missing or does not start with "MediaBrowser".
    /// </summary>
    public static DeviceFingerprint Parse(string? authorizationHeader)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return new DeviceFingerprint();
        }

        var header = authorizationHeader.Trim();

        // Jellyfin/Emby uses the "MediaBrowser" scheme. Some clients also
        // send just the parameters without the scheme prefix.
        var hasScheme = header.StartsWith("MediaBrowser", StringComparison.OrdinalIgnoreCase);
        if (!hasScheme)
        {
            // Still try to parse — some clients send the params without the scheme.
            // But if there are no key="value" pairs, treat it as not a Jellyfin header.
            if (!header.Contains("Client=", StringComparison.OrdinalIgnoreCase) &&
                !header.Contains("Device=", StringComparison.OrdinalIgnoreCase) &&
                !header.Contains("DeviceId=", StringComparison.OrdinalIgnoreCase))
            {
                return new DeviceFingerprint();
            }
        }

        var fp = new DeviceFingerprint { HasHeader = true };
        fp.Client = ExtractField(header, "Client");
        fp.Device = ExtractField(header, "Device");
        fp.DeviceId = ExtractField(header, "DeviceId");
        fp.Version = ExtractField(header, "Version");
        return fp;
    }

    /// <summary>
    /// Extracts a quoted field value from the header. Handles both
    /// Field="Value" and Field=Value formats.
    /// </summary>
    private static string? ExtractField(string header, string fieldName)
    {
        // Match Field="Value" or Field=Value (no quotes)
        var pattern = $@"{fieldName}\s*=\s*(?:""([^""]*)""|([^,;\s]+))";
        var match = Regex.Match(header, pattern, RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            return null;
        }

        // Group 1 = quoted value, Group 2 = unquoted value
        return match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
    }
}
