using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ClientKindClassifierTests
{
    [Theory]
    [InlineData("Mozilla/5.0 Chrome/120", null, ClientKind.Web)]
    [InlineData("Jellyfin Android", null, ClientKind.App)]
    [InlineData("AndroidTV", "MediaBrowser Client=\"Android TV\"", ClientKind.App)]
    [InlineData("curl/8.0", null, ClientKind.Unknown)]
    public void Classifies_Clients(string? ua, string? auth, ClientKind expected)
    {
        Assert.Equal(expected, ClientKindClassifier.Classify(ua, auth));
    }

    // --- Spoofing edge cases ---

    [Fact]
    public void EmptyUserAgent_IsUnknown()
    {
        Assert.Equal(ClientKind.Unknown, ClientKindClassifier.Classify("", null));
    }

    [Fact]
    public void NullUserAgent_IsUnknown()
    {
        Assert.Equal(ClientKind.Unknown, ClientKindClassifier.Classify(null, null));
    }

    [Fact]
    public void WhitespaceOnlyUserAgent_IsUnknown()
    {
        Assert.Equal(ClientKind.Unknown, ClientKindClassifier.Classify("   ", null));
    }

    /// <summary>
    /// A bot that spoofs a TV app User-Agent is classified as App and bypasses
    /// the browser CAPTCHA. This is a known limitation documented in the README
    /// and the threat model. The test pins the current behavior so a future
    /// change to stricter client verification is visible.
    /// </summary>
    [Fact]
    public void BotSpoofingTvAppUserAgent_IsClassifiedAsApp()
    {
        // A raw HTTP client can send any User-Agent string it wants.
        // This one claims to be a Roku client.
        var kind = ClientKindClassifier.Classify("Roku/DVP-9.10", null);
        Assert.Equal(ClientKind.App, kind);
    }

    [Fact]
    public void BotSpoofingAndroidTvUserAgent_IsClassifiedAsApp()
    {
        var kind = ClientKindClassifier.Classify("Android TV", null);
        Assert.Equal(ClientKind.App, kind);
    }

    /// <summary>
    /// A bot that spoofs a browser User-Agent is classified as Web and
    /// will face the CAPTCHA challenge. This is the correct behavior:
    /// if you claim to be a browser, you get the browser challenge.
    /// </summary>
    [Fact]
    public void BotSpoofingBrowserUserAgent_IsClassifiedAsWeb()
    {
        var kind = ClientKindClassifier.Classify("Mozilla/5.0 (compatible; bot/1.0)", null);
        Assert.Equal(ClientKind.Web, kind);
    }

    /// <summary>
    /// A bot that sends a TV app token in the Authorization header but
    /// no recognizable User-Agent is still classified as App. The classifier
    /// checks both fields.
    /// </summary>
    [Fact]
    public void TvAppTokenInAuthorization_IsClassifiedAsApp()
    {
        var kind = ClientKindClassifier.Classify(null, "MediaBrowser Client=\"Infuse\", Device=\"iPhone\"");
        Assert.Equal(ClientKind.App, kind);
    }

    /// <summary>
    /// A bot that sends no recognizable tokens in either field is Unknown.
    /// With CaptchaChallengeUnknown off, it bypasses the challenge.
    /// With CaptchaChallengeUnknown on, it is blocked.
    /// </summary>
    [Fact]
    public void UnrecognizedBotWithRandomUserAgent_IsUnknown()
    {
        var kind = ClientKindClassifier.Classify("python-requests/2.28.0", null);
        Assert.Equal(ClientKind.Unknown, kind);
    }

    [Fact]
    public void KodiClient_IsApp()
    {
        Assert.Equal(ClientKind.App, ClientKindClassifier.Classify("Kodi/20.0", null));
    }

    [Fact]
    public void SwiftfinClient_IsApp()
    {
        Assert.Equal(ClientKind.App, ClientKindClassifier.Classify("Swiftfin/1.0", null));
    }

    [Fact]
    public void XboxClient_IsApp()
    {
        Assert.Equal(ClientKind.App, ClientKindClassifier.Classify("Xbox", null));
    }

    [Fact]
    public void PlayStationClient_IsApp()
    {
        Assert.Equal(ClientKind.App, ClientKindClassifier.Classify("PlayStation", null));
    }

    [Fact]
    public void SafariBrowser_IsWeb()
    {
        Assert.Equal(ClientKind.Web, ClientKindClassifier.Classify("Safari/605.1.15", null));
    }

    [Fact]
    public void EdgeBrowser_IsWeb()
    {
        Assert.Equal(ClientKind.Web, ClientKindClassifier.Classify("Edg/120.0", null));
    }

    [Fact]
    public void JellyfinWeb_IsWeb()
    {
        Assert.Equal(ClientKind.Web, ClientKindClassifier.Classify("Jellyfin Web/10.8", null));
    }

    [Fact]
    public void JellyfinMediaPlayer_IsApp()
    {
        // The official desktop client identifies as "Jellyfin Media Player" in
        // the authorization header; it must not fall through to Web/Unknown.
        var header = "MediaBrowser Client=\"Jellyfin Media Player\", Device=\"PC\", DeviceId=\"abc123\", Version=\"1.11.0\"";
        Assert.Equal(ClientKind.App, ClientKindClassifier.Classify(string.Empty, header));
    }
}
