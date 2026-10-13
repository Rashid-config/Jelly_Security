using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class DeviceFingerprintTests
{
    // --- Parsing ---

    [Fact]
    public void Parse_FullHeader_ExtractsAllFields()
    {
        var fp = DeviceFingerprint.Parse(
            "MediaBrowser Client=\"Jellyfin Android\", Device=\"Pixel 8\", DeviceId=\"abc-123-device\", Version=\"2.5.0\"");

        Assert.True(fp.HasHeader);
        Assert.Equal("Jellyfin Android", fp.Client);
        Assert.Equal("Pixel 8", fp.Device);
        Assert.Equal("abc-123-device", fp.DeviceId);
        Assert.Equal("2.5.0", fp.Version);
        Assert.True(fp.HasClient);
        Assert.True(fp.HasDeviceId);
    }

    [Fact]
    public void Parse_NullHeader_ReturnsEmpty()
    {
        var fp = DeviceFingerprint.Parse(null);
        Assert.False(fp.HasHeader);
        Assert.False(fp.HasClient);
        Assert.False(fp.HasDeviceId);
    }

    [Fact]
    public void Parse_EmptyHeader_ReturnsEmpty()
    {
        var fp = DeviceFingerprint.Parse("");
        Assert.False(fp.HasHeader);
    }

    [Fact]
    public void Parse_NonMediaBrowserHeader_ReturnsEmpty()
    {
        // A Bearer token or other scheme is not a Jellyfin client header.
        var fp = DeviceFingerprint.Parse("Bearer eyJhbGciOiJIUzI1NiJ9.token");
        Assert.False(fp.HasHeader);
    }

    [Fact]
    public void Parse_HeaderWithoutDeviceId_HasHeaderButNoDeviceId()
    {
        var fp = DeviceFingerprint.Parse(
            "MediaBrowser Client=\"Infuse\", Device=\"iPhone\"");

        Assert.True(fp.HasHeader);
        Assert.True(fp.HasClient);
        Assert.False(fp.HasDeviceId);
        Assert.Equal("Infuse", fp.Client);
    }

    [Fact]
    public void Parse_MediaBrowserSchemeOnly_HasHeaderButNoFields()
    {
        var fp = DeviceFingerprint.Parse("MediaBrowser");
        Assert.True(fp.HasHeader);
        Assert.False(fp.HasClient);
        Assert.False(fp.HasDeviceId);
    }

    [Fact]
    public void Parse_ParametersWithoutScheme_StillParses()
    {
        // Some clients may send the params without the MediaBrowser prefix.
        var fp = DeviceFingerprint.Parse(
            "Client=\"Jellyfin Web\", Device=\"Chrome on Windows\", DeviceId=\"xyz\"");

        Assert.True(fp.HasHeader);
        Assert.Equal("Jellyfin Web", fp.Client);
        Assert.Equal("xyz", fp.DeviceId);
    }

    [Fact]
    public void Parse_UnquotedValues_StillParses()
    {
        var fp = DeviceFingerprint.Parse("MediaBrowser Client=Finamp, DeviceId=abc123");
        Assert.Equal("Finamp", fp.Client);
        Assert.Equal("abc123", fp.DeviceId);
    }

    [Fact]
    public void Parse_DeviceWithCommaInName_StopsAtFieldEnd()
    {
        // Quoted value containing a comma must not be cut short.
        var fp = DeviceFingerprint.Parse(
            "MediaBrowser Client=\"Infuse\", Device=\"iPhone 15, Pro\", DeviceId=\"dev-1\"");

        Assert.Equal("iPhone 15, Pro", fp.Device);
        Assert.Equal("dev-1", fp.DeviceId);
    }

    // --- Strict mode classification ---

    [Fact]
    public void Strict_SpoofedTvUA_NoDeviceId_IsUnknown()
    {
        // The core scenario: a bot sends "Roku" as User-Agent but has no
        // authorization header — in strict mode it is NOT trusted as an app.
        var kind = ClientKindClassifier.Classify(
            "Roku/DVP-9.10", null, strictDeviceFingerprint: true);

        Assert.Equal(ClientKind.Unknown, kind);
    }

    [Fact]
    public void Strict_SpoofedTvUA_WithDeviceId_IsApp()
    {
        // A real Roku client sends a proper authorization header with DeviceId.
        var kind = ClientKindClassifier.Classify(
            "Roku/DVP-9.10",
            "MediaBrowser Client=\"Jellyfin Roku\", Device=\"Roku Ultra\", DeviceId=\"roku-uuid-1234\"",
            strictDeviceFingerprint: true);

        Assert.Equal(ClientKind.App, kind);
    }

    [Fact]
    public void Strict_AndroidTvUA_HeaderHasClientButNoDeviceId_IsUnknown()
    {
        // A bot that learned to send a Client field but still no DeviceId.
        var kind = ClientKindClassifier.Classify(
            "Android TV",
            "MediaBrowser Client=\"Jellyfin Android\"",
            strictDeviceFingerprint: true);

        Assert.Equal(ClientKind.Unknown, kind);
    }

    [Fact]
    public void Strict_AndroidTvUA_HeaderHasClientAndDeviceId_IsApp()
    {
        var kind = ClientKindClassifier.Classify(
            "Android TV",
            "MediaBrowser Client=\"Jellyfin Android\", Device=\"Shield TV\", DeviceId=\"nv-shield-99\"",
            strictDeviceFingerprint: true);

        Assert.Equal(ClientKind.App, kind);
    }

    [Fact]
    public void Strict_BrowserUA_StillWeb()
    {
        // Strict mode only affects App claims — browsers are unaffected.
        var kind = ClientKindClassifier.Classify(
            "Mozilla/5.0 Chrome/120",
            "MediaBrowser Client=\"Jellyfin Web\", DeviceId=\"web-123\"",
            strictDeviceFingerprint: true);

        Assert.Equal(ClientKind.Web, kind);
    }

    [Fact]
    public void Strict_UnrecognizedClient_StillUnknown()
    {
        var kind = ClientKindClassifier.Classify(
            "python-requests/2.28.0", null, strictDeviceFingerprint: true);

        Assert.Equal(ClientKind.Unknown, kind);
    }

    // --- Non-strict (default) mode unchanged ---

    [Fact]
    public void Default_SpoofedTvUA_StillApp()
    {
        // Without strict mode, the old behavior is preserved: a spoofed TV
        // User-Agent is classified as App. Documented limitation.
        var kind = ClientKindClassifier.Classify(
            "Roku/DVP-9.10", null, strictDeviceFingerprint: false);

        Assert.Equal(ClientKind.App, kind);
    }

    [Fact]
    public void Default_OldOverload_BehavesLikeNonStrict()
    {
        // The two-argument overload defaults to non-strict.
        var kind = ClientKindClassifier.Classify("Android TV", null);
        Assert.Equal(ClientKind.App, kind);
    }
}
