using Jellyfin.Plugin.JellySecurity.Core.Sessions;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class SessionWatchPolicyTests
{
    [Fact]
    public void FirstAddress_IsRememberedQuietly()
    {
        var book = new KnownAddressBook();
        var first = book.Note("family", "203.0.113.10");
        Assert.True(first.Changed);
        Assert.False(first.Alert);
        Assert.False(book.Note("family", "203.0.113.10").Alert);
    }

    [Fact]
    public void LaterAddress_AlertsWithoutForgettingTheFirst()
    {
        var book = new KnownAddressBook();
        book.Note("family", "203.0.113.10");
        var next = book.Note("family", "198.51.100.8");
        Assert.True(next.Alert);
        Assert.True(book.Contains("family", "203.0.113.10"));
        Assert.True(book.Contains("family", "198.51.100.8"));
    }

    [Fact]
    public void FourSessions_IsTheDefaultCrowd()
    {
        Assert.False(SessionWatchPolicy.TooMany(3, 0));
        Assert.True(SessionWatchPolicy.TooMany(4, 0));
        Assert.Equal(2, SessionWatchPolicy.ConcurrentLimit(1));
    }

    [Fact]
    public void PlayingDevice_IsNotClosed()
    {
        var closed = SessionWatchPolicy.DevicesToClose(
            ["tv", "phone", "browser"],
            ["tv"]);
        Assert.Equal(["phone", "browser"], closed);
    }

    [Fact]
    public void UnknownPlayingDevice_ClosesNothing()
    {
        var closed = SessionWatchPolicy.DevicesToClose(["tv", "phone"], [null]);
        Assert.Empty(closed);
    }

    [Fact]
    public void EndpointWithPort_KeepsTheAddress()
    {
        Assert.Equal("203.0.113.10", SessionWatchPolicy.NormalizeEndpoint("203.0.113.10:443"));
        Assert.Equal("2001:db8::1", SessionWatchPolicy.NormalizeEndpoint("[2001:db8::1]:8096"));
    }
}
