using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ReconPathClassifierTests
{
    // --- Collection/enumeration endpoints that DO count ---

    [Theory]
    [InlineData("/Users")]
    [InlineData("/Users/Public")]
    [InlineData("/Users/Me")]
    [InlineData("/Items")]
    [InlineData("/Items?ParentId=abc&Recursive=true")]
    [InlineData("/Shows")]
    [InlineData("/Shows/NextUp")]
    [InlineData("/Artists")]
    [InlineData("/Albums")]
    [InlineData("/Genres")]
    [InlineData("/Studios")]
    [InlineData("/Persons")]
    [InlineData("/Library")]
    [InlineData("/Library/MediaFolders")]
    [InlineData("/Library/VirtualFolders")]
    [InlineData("/System")]
    [InlineData("/System/Info")]
    [InlineData("/System/Info/Public")]
    [InlineData("/System/Configuration")]
    [InlineData("/Sessions")]
    [InlineData("/Plugins")]
    [InlineData("/ScheduledTasks")]
    [InlineData("/ActivityLog/Entries")]
    [InlineData("/UserViews")]
    [InlineData("/Suggestions")]
    [InlineData("/Playlists")]
    [InlineData("/Collections")]
    [InlineData("/Localization")]
    [InlineData("/api-docs")]
    [InlineData("/api-docs/openapi.json")]
    [InlineData("/swagger")]
    [InlineData("/QuickConnect/List")]
    public void ApiSurface_Counts(string path)
    {
        Assert.True(ReconPathClassifier.IsApiSurface(path));
    }

    // --- Playback, per-item, and infra paths that NEVER count ---

    [Theory]
    [InlineData("/Videos/abc123/stream.mp4")]
    [InlineData("/Audio/abc123/universal")]
    [InlineData("/Items/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Images/Primary")]
    [InlineData("/Items/8b4e2c1a6d3f4a199e2b7c5f1d8a0b34/Images/Backdrop")]
    [InlineData("/Users/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Images/Primary")]
    [InlineData("/Items/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34")]
    [InlineData("/Items/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/Similar")]
    [InlineData("/Items/8b4e2c1a-6d3f-4a19-9e2b-7c5f1d8a0b34/PlaybackInfo")]
    [InlineData("/Items/abc/Download")]
    [InlineData("/Items/abc/Subtitles/3/Stream.vtt")]
    [InlineData("/web/index.html")]
    [InlineData("/web/modules/somepage.html")]
    [InlineData("/socket")]
    [InlineData("/embywebsocket")]
    [InlineData("/Videos/x/hls1/main.m3u8")]
    [InlineData("/Sessions/Playing/Progress")]
    [InlineData("/Items/very/deep/path/with/many/segments/here")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/NotARealEndpoint")]
    [InlineData("/web")]
    public void NotApiSurface_DoesNotCount(string? path)
    {
        Assert.False(ReconPathClassifier.IsApiSurface(path));
    }

    [Fact]
    public void ItemIdThatIsNotAGuid_ButNoDeepKeyword_StillCounts()
    {
        // A scanner enumerating numeric ids (/Items/1, /Items/2) gets 404s —
        // that probing should count. Only GUID-shaped segments are excluded.
        Assert.True(ReconPathClassifier.IsApiSurface("/Items/12345"));
    }

    [Fact]
    public void SignInPostPath_ClassifiesAsSurfaceButReachesAuthFirst()
    {
        // /Users/AuthenticateByName is on the surface allowlist, but POSTs to
        // it are classified AuthPathKind.Password by AuthPathClassifier before
        // the recon branch runs — so sign-in handling stays unchanged.
        Assert.True(ReconPathClassifier.IsApiSurface("/Users/AuthenticateByName"));
    }

    [Fact]
    public void CaseIsIgnored()
    {
        Assert.True(ReconPathClassifier.IsApiSurface("/system/info/public"));
        Assert.True(ReconPathClassifier.IsApiSurface("/LIBRARY/VIRTUALFOLDERS"));
    }
}
