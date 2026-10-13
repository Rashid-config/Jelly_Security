namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Best-effort client class. Apps and unknown clients never receive a CAPTCHA challenge.
/// Uses both User-Agent and the Jellyfin authorization header fingerprint.
/// A client that claims to be a TV app in User-Agent but sends no DeviceId
/// in the authorization header is downgraded to Unknown — a real TV client
/// always sends a DeviceId.
/// </summary>
public static class ClientKindClassifier
{
    public static ClientKind Classify(string? userAgent, string? authorization)
    {
        return Classify(userAgent, authorization, strictDeviceFingerprint: false);
    }

    /// <summary>
    /// Classifies the client. When <paramref name="strictDeviceFingerprint"/> is on,
    /// a client that claims to be a TV app in User-Agent but sends no DeviceId
    /// in the authorization header is downgraded from App to Unknown. This closes
    /// the User-Agent spoofing path for bots that don't send a proper Jellyfin
    /// authorization header. Off by default — some older or custom clients may
    /// not send a DeviceId.
    /// </summary>
    public static ClientKind Classify(string? userAgent, string? authorization, bool strictDeviceFingerprint)
    {
        var fingerprint = DeviceFingerprint.Parse(authorization);
        var blob = $"{userAgent} {authorization}";

        // Check the fingerprint first — it's stronger than User-Agent.
        // A real Jellyfin client sends Client="..." in the authorization header.
        if (fingerprint.HasClient)
        {
            var clientKind = ClassifyByClientName(fingerprint.Client!);
            if (clientKind is ClientKind.App)
            {
                // The fingerprint says this is an app. If strict mode is on,
                // require a DeviceId too — a real app always sends one.
                if (strictDeviceFingerprint && !fingerprint.HasDeviceId)
                {
                    return ClientKind.Unknown;
                }
                return ClientKind.App;
            }
            if (clientKind is ClientKind.Web)
            {
                return ClientKind.Web;
            }
        }

        // Fall back to User-Agent + authorization blob matching.
        if (ContainsAny(blob, "AndroidTV", "Android TV", "Kodi", "Infuse", "Findroid", "Swiftfin", "Jellyfin-Android", "Jellyfin Android", "Roku", "Xbox", "PlayStation"))
        {
            // User-Agent says TV app. In strict mode, require a DeviceId
            // from the authorization header to confirm it's a real app.
            if (strictDeviceFingerprint && !fingerprint.HasDeviceId)
            {
                return ClientKind.Unknown;
            }
            return ClientKind.App;
        }

        if (ContainsAny(blob, "Jellyfin Web", "Mozilla/", "Chrome/", "Safari/", "Edg/"))
        {
            return ClientKind.Web;
        }

        return ClientKind.Unknown;
    }

    /// <summary>
    /// Classifies by the Client field from the authorization header.
    /// Returns null if the client name is not recognized.
    /// </summary>
    private static ClientKind? ClassifyByClientName(string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
        {
            return null;
        }

        // Jellyfin Web is the browser client.
        if (clientName.Contains("Jellyfin Web", StringComparison.OrdinalIgnoreCase) ||
            clientName.Contains("JellyfinWeb", StringComparison.OrdinalIgnoreCase))
        {
            return ClientKind.Web;
        }

        // Known TV/mobile app client names.
        if (ContainsAny(clientName, "Jellyfin Android", "Jellyfin-Android", "Jellyfin iOS",
            "Jellyfin TV", "AndroidTV", "Android TV", "Kodi", "Infuse", "Findroid",
            "Swiftfin", "Roku", "Jellyfin Roku", "Gelli", "Finamp", "Jellyfin MPV",
            "Jellyfin Desktop", "Jellyfin Media Player", "Jellyfin Mobile"))
        {
            return ClientKind.App;
        }

        // Any other Client value that isn't recognized — could be a custom
        // client or a bot. Treat as unknown so the UA fallback can decide.
        return null;
    }

    private static bool ContainsAny(string value, params string[] tokens)
    {
        return tokens.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase));
    }
}
