using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Integration;

/// <summary>
/// Adds the reCAPTCHA script to the browser shell response.
/// Compressed shells are decoded first so nginx gzip and Brotli still receive the check.
/// Static Jellyfin web files are left untouched.
/// </summary>
public sealed class CaptchaPageMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityEngine _engine;

    public CaptchaPageMiddleware(RequestDelegate next, SecurityEngine engine)
    {
        _next = next;
        _engine = engine;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!ShouldRewrite(context.Request))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Ask the rest of the pipeline, including response compression, for plain HTML.
        // A proxy in front can compress the injected page on the way to the browser.
        // Drop validators so a browser holding the old shell cannot be told the file is unchanged.
        context.Request.Headers.AcceptEncoding = "identity";
        LoginPageCache.BypassValidation(context.Request);
        var original = context.Response.Body;
        await using var buffer = new MemoryStream();
        context.Response.Body = buffer;
        var included = false;
        byte[]? plain = null;
        context.Response.OnStarting(() =>
        {
            if (included && plain is not null)
            {
                LoginPageCache.PreventReuse(context.Response);
                context.Response.ContentLength = plain.Length;
            }

            return Task.CompletedTask;
        });

        try
        {
            await _next(context).ConfigureAwait(false);
            var payload = buffer.ToArray();
            var rewritten = CaptchaPageRewriter.Rewrite(
                context.Response.StatusCode,
                context.Response.ContentType,
                context.Response.Headers.ContentEncoding,
                payload,
                _engine.Config.CaptchaSiteKey,
                _engine.Config.CaptchaProvider);
            context.Response.Body = original;
            if (!rewritten.Included || context.Response.HasStarted)
            {
                await original.WriteAsync(payload, context.RequestAborted).ConfigureAwait(false);
                return;
            }

            included = true;
            plain = rewritten.Body;
            LoginPageCache.PreventReuse(context.Response);
            context.Response.ContentLength = plain.Length;
            await original.WriteAsync(plain, context.RequestAborted).ConfigureAwait(false);
        }
        finally
        {
            context.Response.Body = original;
        }
    }

    private bool ShouldRewrite(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method) || !CaptchaPolicy.IsReady(_engine.Config))
        {
            return false;
        }

        var path = request.Path.Value ?? "/";
        return path.Equals("/", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/web", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/web/", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/index.html", StringComparison.OrdinalIgnoreCase);
    }
}
