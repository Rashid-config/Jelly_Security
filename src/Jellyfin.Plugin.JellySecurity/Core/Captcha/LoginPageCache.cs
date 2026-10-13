using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Stops browsers and proxies from keeping a sign-in page that was saved before the check was inserted.
/// A conditional request for that old page is answered with the current page, not with "not modified".
/// </summary>
public static class LoginPageCache
{
    public static void BypassValidation(HttpRequest request)
    {
        request.Headers.Remove("If-None-Match");
        request.Headers.Remove("If-Modified-Since");
        request.Headers.Remove("If-Match");
        request.Headers.Remove("If-Range");
    }

    public static void PreventReuse(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
        response.Headers.Vary = "Accept-Encoding";
        response.Headers.Remove("ETag");
        response.Headers.Remove("Last-Modified");
        response.Headers.Remove("Content-MD5");
        response.Headers.Remove("Age");
        response.Headers.Remove("Content-Encoding");
    }
}
