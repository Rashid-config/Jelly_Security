using System.Net.Mime;
using System.Text;
using System.Text.Json;
using System.Threading;
using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Policies;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Integration;

/// <summary>
/// Observes sign-in, mapped admin writes, and optional session administration.
/// Playback routes are never classified and pass through.
/// A failure inside the guard never replaces Jellyfin authentication.
/// </summary>
public sealed class AuthGuardMiddleware
{
    private const int MaxBodySniffBytes = 65536;

    /// <summary>
    /// Maximum number of sign-in requests that may be delayed simultaneously.
    /// When this many are already waiting, further delays are skipped so the
    /// request reaches Jellyfin immediately. This bounds slow-loris exposure:
    /// an attacker cannot hold an unbounded number of connections open.
    /// </summary>
    private const int MaxConcurrentDelays = 64;

    private static int _activeDelays;

    private readonly RequestDelegate _next;
    private readonly SecurityEngine _engine;
    private readonly CaptchaVerifier _captcha;

    public AuthGuardMiddleware(RequestDelegate next, SecurityEngine engine, CaptchaVerifier captcha)
    {
        _next = next;
        _engine = engine;
        _captcha = captcha;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        GuardPlan plan;
        try
        {
            plan = await PlanAsync(context).ConfigureAwait(false);
        }
        catch (Exception)
        {
            if (context.RequestAborted.IsCancellationRequested || context.Response.HasStarted)
            {
                return;
            }

            await _next(context).ConfigureAwait(false);
            return;
        }

        if (plan.Completed)
        {
            return;
        }

        await _next(context).ConfigureAwait(false);
        if (plan.Observe)
        {
            SafeObserve(plan.Identity, plan.Path, plan.Username, context.Response.StatusCode, false);
        }
        else if (plan.Recon)
        {
            SafeRecon(plan.Identity, plan.Path, plan.HasToken, context.Response.StatusCode);
        }
    }

    private async Task<GuardPlan> PlanAsync(HttpContext context)
    {
        var kind = AuthPathClassifier.Classify(context.Request);
        if (kind == AuthPathKind.None)
        {
            var reconPath = context.Request.Path.Value ?? string.Empty;
            if (!_engine.Config.ReconWatchEnabled || !ReconPathClassifier.IsApiSurface(reconPath))
            {
                return GuardPlan.PassThrough();
            }

            var reconIdentity = _engine.Resolve(context);
            var hasToken = HasAuthToken(context.Request);
            var limit = _engine.EvaluateReconLimit(reconIdentity);
            if (limit.Block)
            {
                context.Response.Headers.RetryAfter = limit.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
                await WriteJsonAsync(context, StatusCodes.Status429TooManyRequests, "{\"Message\":\"API enumeration rate limit exceeded. Slow down and retry later.\"}").ConfigureAwait(false);
                SafeRecon(reconIdentity, reconPath, hasToken, StatusCodes.Status429TooManyRequests);
                return GuardPlan.Done();
            }

            return new GuardPlan(false, false, reconIdentity, reconPath, null, Recon: true, HasToken: hasToken);
        }

        var path = context.Request.Path.Value ?? string.Empty;
        var identity = _engine.Resolve(context);
        if (kind == AuthPathKind.Session)
        {
            return new GuardPlan(false, _engine.Config.ObserveSessions, identity, path, null);
        }

        if (kind == AuthPathKind.Admin)
        {
            var admin = _engine.EvaluateAdminAccess(identity);
            if (admin.Block)
            {
                await WriteJsonAsync(context, StatusCodes.Status403Forbidden, "{\"Message\":\"This mapped admin route is limited to Admin Networks. Coverage is partial.\"}").ConfigureAwait(false);
                SafeObserve(identity, path, null, StatusCodes.Status403Forbidden, true, "Admin route blocked: this address is outside the configured Admin Networks. " + admin.Reason);
                return GuardPlan.Done();
            }

            return new GuardPlan(false, true, identity, path, null);
        }

        context.Request.EnableBuffering();
        var username = await TryReadUsernameAsync(context.Request).ConfigureAwait(false);
        var captchaToken = context.Request.Headers["X-Jelly-Security-Captcha"].ToString();
        var userAgent = context.Request.Headers.UserAgent.ToString();
        var authorization = context.Request.Headers.Authorization.ToString();
        var client = ClientKindClassifier.Classify(userAgent, authorization, _engine.Config.StrictDeviceFingerprint);
        var check = CaptchaCheck.Absent;
        if (CaptchaPolicy.NeedsVerification(_engine.Config, kind, client))
        {
            if (captchaToken.Length > 4096)
            {
                check = CaptchaCheck.Rejected;
            }
            else if (captchaToken.Length > 0)
            {
                var remoteIp = identity.Trust == SourceTrust.Verified ? identity.Address : null;
                check = await _captcha.VerifyAsync(
                    _engine.Config,
                    captchaToken,
                    remoteIp,
                    context.Request.Host.Host,
                    context.RequestAborted).ConfigureAwait(false);
            }
        }

        var captcha = _engine.EvaluateCaptcha(kind, userAgent, authorization, check);
        if (captcha.Block)
        {
            var captchaReason = check == CaptchaCheck.Absent
                ? "Browser sign-in blocked: no CAPTCHA token provided."
                : check == CaptchaCheck.Rejected
                    ? "Browser sign-in blocked: CAPTCHA token was rejected by the provider."
                    : "Browser sign-in blocked: CAPTCHA verification is required for this client.";
            await WriteJsonAsync(context, StatusCodes.Status403Forbidden, "{\"Message\":\"Web CAPTCHA is required for this client.\"}").ConfigureAwait(false);
            SafeObserve(identity, path, username, StatusCodes.Status403Forbidden, true, captchaReason);
            return GuardPlan.Done();
        }

        var cooldown = _engine.PlanAccountCooldown(kind, identity, username);
        if (cooldown.Block)
        {
            context.Response.Headers.RetryAfter = cooldown.RemainingSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var cooldownReason = "Sign-in paused by plugin cooldown for this username (" + cooldown.RemainingSeconds + "s remaining). The Jellyfin account stays enabled.";
            await WriteJsonAsync(context, StatusCodes.Status429TooManyRequests, "{\"Message\":\"Sign-in for this name is paused by a temporary plugin cooldown. The Jellyfin account stays enabled.\"}").ConfigureAwait(false);
            SafeObserve(identity, path, username, StatusCodes.Status429TooManyRequests, true, cooldownReason);
            return GuardPlan.Done();
        }

        var decision = _engine.AppliesSignInBan(kind)
            ? _engine.EvaluatePreAuth(identity, path)
            : BanDecision.Allow("This path is observed only.");
        if (!decision.Block)
        {
            var delay = _engine.PlanPasswordDelay(kind, identity);
            if (delay.Delay > TimeSpan.Zero)
            {
                // Bound the number of simultaneously-delayed connections so
                // a slow-loris attacker cannot hold an unbounded number of
                // sockets. When the limit is reached, skip the delay and let
                // the request continue to Jellyfin immediately. The delay
                // is a soft control, not a hard gate.
                if (Interlocked.Increment(ref _activeDelays) <= MaxConcurrentDelays)
                {
                    try
                    {
                        await Task.Delay(delay.Delay, context.RequestAborted).ConfigureAwait(false);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _activeDelays);
                    }
                }
                else
                {
                    Interlocked.Decrement(ref _activeDelays);
                }
            }

            return new GuardPlan(false, true, identity, path, username);
        }

        var body = "{\"Message\":\"Sign-in from this address is temporarily blocked.\"}";
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        var banReason = decision.Reason;
        if (decision.Ban?.ExpiresUtc is { } expires)
        {
            var seconds = Math.Max(1, (int)Math.Ceiling((expires - DateTimeOffset.UtcNow).TotalSeconds));
            context.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            banReason += " (" + seconds + "s remaining)";
        }

        var banKind = decision.Ban?.Kind switch
        {
            BanKind.Manual => "manual ban",
            BanKind.Cidr => "CIDR ban",
            BanKind.AutomaticTemporary => "automatic temporary ban",
            BanKind.Progressive => "progressive ban (strike " + (decision.Ban?.Strike ?? 0) + ")",
            BanKind.Geo => "country block",
            BanKind.AutomaticPrefix => "automatic IPv6 prefix ban (strike " + (decision.Ban?.Strike ?? 0) + ")",
            _ => "ban"
        };
        var fullBanReason = "Sign-in blocked by " + banKind + ". " + banReason;

        context.Response.ContentType = MediaTypeNames.Application.Json;
        await context.Response.WriteAsync(body).ConfigureAwait(false);
        SafeObserve(identity, path, username, StatusCodes.Status429TooManyRequests, true, fullBanReason);
        return GuardPlan.Done();
    }

    private static async Task WriteJsonAsync(HttpContext context, int statusCode, string body)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = MediaTypeNames.Application.Json;
        await context.Response.WriteAsync(body).ConfigureAwait(false);
    }

    private void SafeObserve(ClientIdentity? identity, string path, string? username, int statusCode, bool enforced, string? blockReason = null)
    {
        if (identity is null)
        {
            return;
        }

        try
        {
            _engine.Observe(identity, path, username, statusCode, enforced, blockReason);
        }
        catch (Exception)
        {
            // Observation must not turn a completed sign-in into an error.
        }
    }

    private void SafeRecon(ClientIdentity? identity, string path, bool hasToken, int statusCode)
    {
        if (identity is null)
        {
            return;
        }

        try
        {
            _engine.ObserveApiRequest(identity, path, hasToken, statusCode);
        }
        catch (Exception)
        {
            // Observation must not turn a completed request into an error.
        }
    }

    /// <summary>
    /// Cheap presence check for any auth token — Authorization Token=,
    /// the legacy X-Emby-Token / X-MediaBrowser-Token headers, or the api_key
    /// query parameters. It does not validate the token: requests carrying a
    /// bad token still count as failures when Jellyfin rejects them.
    /// </summary>
    private static bool HasAuthToken(HttpRequest request)
    {
        if (request.Headers.Authorization.ToString().Contains("Token=", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (request.Headers.ContainsKey("X-Emby-Token") || request.Headers.ContainsKey("X-MediaBrowser-Token"))
        {
            return true;
        }

        return request.Query.ContainsKey("api_key") || request.Query.ContainsKey("ApiKey");
    }

    private static async Task<string?> TryReadUsernameAsync(HttpRequest request)
    {
        try
        {
            if (request.ContentLength is 0 || !request.Body.CanSeek)
            {
                return null;
            }

            request.Body.Position = 0;
            var buffer = new byte[MaxBodySniffBytes];
            var read = await request.Body.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false);
            request.Body.Position = 0;
            if (read == 0)
            {
                return null;
            }

            var json = Encoding.UTF8.GetString(buffer, 0, read);
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (document.RootElement.TryGetProperty("Username", out var username))
            {
                return username.GetString();
            }

            if (document.RootElement.TryGetProperty("username", out var lower))
            {
                return lower.GetString();
            }
        }
        catch (Exception)
        {
            try
            {
                if (request.Body.CanSeek)
                {
                    request.Body.Position = 0;
                }
            }
            catch (Exception)
            {
                // The request can still continue without a username.
            }
        }

        return null;
    }

    private readonly record struct GuardPlan(bool Completed, bool Observe, ClientIdentity? Identity, string Path, string? Username, bool Recon = false, bool HasToken = false)
    {
        public static GuardPlan PassThrough() => new(false, false, null, string.Empty, null);

        public static GuardPlan Done() => new(true, false, null, string.Empty, null);
    }
}
