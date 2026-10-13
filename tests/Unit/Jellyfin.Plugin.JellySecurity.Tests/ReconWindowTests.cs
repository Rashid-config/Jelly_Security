using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ReconWindowTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    [Fact]
    public void FailedRequests_AreCounted()
    {
        var w = new ReconWindow();
        for (var i = 0; i < 10; i++)
        {
            w.Record("/Users", hasToken: false, 401, T0.AddSeconds(i), Window);
        }

        var a = w.Record("/Items", hasToken: false, 401, T0.AddSeconds(10), Window);
        Assert.Equal(11, a.Failed);
        Assert.Equal(11, a.Unauth);
        Assert.Equal(2, a.DistinctPaths);
    }

    [Fact]
    public void SuccessfulRequests_DoNotCountAsFailed()
    {
        var w = new ReconWindow();
        w.Record("/Users", hasToken: true, 200, T0, Window);
        w.Record("/Items", hasToken: true, 200, T0, Window);
        var a = w.Record("/Library", hasToken: true, 200, T0, Window);

        Assert.Equal(0, a.Failed);
        Assert.Equal(0, a.Unauth);
        Assert.Equal(3, a.DistinctPaths);
    }

    [Fact]
    public void AuthenticatedRequests_DoNotCountAsUnauth()
    {
        var w = new ReconWindow();
        var a = w.Record("/Users", hasToken: true, 200, T0, Window);
        Assert.Equal(0, a.Unauth);
    }

    [Fact]
    public void OldHits_PruneOutOfWindow()
    {
        var w = new ReconWindow();
        for (var i = 0; i < 40; i++)
        {
            w.Record("/Users", hasToken: false, 401, T0.AddSeconds(i), Window);
        }

        // All earlier hits are now outside the 5-minute window.
        var a = w.Record("/Items", hasToken: false, 401, T0.AddMinutes(6), Window);
        Assert.Equal(1, a.Failed);
        Assert.Equal(1, a.Unauth);
    }

    [Fact]
    public void ReportFlag_GivesOneCrossingPerEpisode()
    {
        var w = new ReconWindow();
        Assert.True(w.TakeReportFlag());
        Assert.False(w.TakeReportFlag());
        Assert.False(w.TakeReportFlag());
    }

    [Fact]
    public void ReportFlag_ResetsWhenWindowFullyExpires()
    {
        var w = new ReconWindow();
        w.Record("/Users", hasToken: false, 401, T0, Window);
        Assert.True(w.TakeReportFlag());
        Assert.False(w.TakeReportFlag());

        // All hits expire — next episode reports again.
        w.Record("/Items", hasToken: false, 401, T0.AddMinutes(6), Window);
        Assert.True(w.TakeReportFlag());
    }

    [Fact]
    public void DistinctPaths_Capped()
    {
        var w = new ReconWindow();
        for (var i = 0; i < 60; i++)
        {
            w.Record($"/Items/p{i}", hasToken: false, 404, T0.AddMilliseconds(i), Window);
        }

        var a = w.Record("/Users", hasToken: false, 404, T0.AddSeconds(1), Window);
        Assert.Equal(48, a.DistinctPaths);
    }

    [Fact]
    public void Limit_IsTimeBounded()
    {
        var w = new ReconWindow();
        Assert.False(w.IsLimited(T0));

        w.LimitUntil(T0.AddMinutes(10));
        Assert.True(w.IsLimited(T0));
        Assert.True(w.IsLimited(T0.AddMinutes(9)));
        Assert.False(w.IsLimited(T0.AddMinutes(11)));
    }

    [Fact]
    public void Status500_DoesNotCountAsFailure()
    {
        // Server errors are Jellyfin's problem, not client probing.
        var w = new ReconWindow();
        var a = w.Record("/Users", hasToken: false, 500, T0, Window);
        Assert.Equal(0, a.Failed);
        Assert.Equal(1, a.Unauth); // still an unauthenticated request
    }

    [Fact]
    public void ClearLimit_EndsActiveLimit()
    {
        var w = new ReconWindow();
        w.LimitUntil(T0.AddMinutes(10));
        Assert.True(w.IsLimited(T0));

        Assert.True(w.ClearLimit(T0.AddMinutes(1)));
        Assert.False(w.IsLimited(T0.AddMinutes(1)));
    }

    [Fact]
    public void ClearLimit_ReturnsFalse_WhenNothingActive()
    {
        var w = new ReconWindow();
        Assert.False(w.ClearLimit(T0));

        // An expired limit counts as not active.
        w.LimitUntil(T0.AddMinutes(10));
        Assert.False(w.ClearLimit(T0.AddMinutes(11)));
        Assert.Null(w.LimitedUntilUtc);
    }

    [Fact]
    public void All4xx_CountAsFailures()
    {
        var w = new ReconWindow();
        w.Record("/Users", false, 401, T0, Window);
        w.Record("/Users", false, 403, T0, Window);
        w.Record("/Users", false, 404, T0, Window);
        var a = w.Record("/Users", false, 429, T0, Window);
        Assert.Equal(4, a.Failed);
    }
}
