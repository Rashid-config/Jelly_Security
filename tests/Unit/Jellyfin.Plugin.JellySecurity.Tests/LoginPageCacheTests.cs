using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class LoginPageCacheTests
{
    [Fact]
    public void BypassValidation_DropsConditionalHeaders()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["If-None-Match"] = "\"old-shell\"";
        context.Request.Headers["If-Modified-Since"] = "Mon, 05 Oct 2026 22:56:32 GMT";
        context.Request.Headers["If-Match"] = "\"old-shell\"";
        context.Request.Headers["If-Range"] = "\"old-shell\"";

        LoginPageCache.BypassValidation(context.Request);

        Assert.False(context.Request.Headers.ContainsKey("If-None-Match"));
        Assert.False(context.Request.Headers.ContainsKey("If-Modified-Since"));
        Assert.False(context.Request.Headers.ContainsKey("If-Match"));
        Assert.False(context.Request.Headers.ContainsKey("If-Range"));
    }

    [Fact]
    public void PreventReuse_ReplacesACachedShell()
    {
        var context = new DefaultHttpContext();
        context.Response.Headers.CacheControl = "no-cache";
        context.Response.Headers.ETag = "\"1dd551cc398c541\"";
        context.Response.Headers.LastModified = "Mon, 05 Oct 2026 22:56:32 GMT";
        context.Response.Headers["Content-Encoding"] = "br";

        LoginPageCache.PreventReuse(context.Response);

        Assert.Contains("no-store", context.Response.Headers.CacheControl.ToString(), StringComparison.Ordinal);
        Assert.False(context.Response.Headers.ContainsKey("ETag"));
        Assert.False(context.Response.Headers.ContainsKey("Last-Modified"));
        Assert.False(context.Response.Headers.ContainsKey("Content-Encoding"));
        Assert.Equal("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }
}
