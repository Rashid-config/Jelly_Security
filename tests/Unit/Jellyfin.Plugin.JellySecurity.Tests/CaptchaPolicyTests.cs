using System.IO.Compression;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Integration;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class CaptchaPolicyTests
{
    private const string SiteKey = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";
    private const string Secret = "6LeIxAcTAAAAAGG-vFI1TnajQZxnqKz7x0p0a0s0";

    [Fact]
    public void NeverChallenges_Apps()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: false), AuthPathKind.Password, ClientKind.App, CaptchaCheck.Absent);
        Assert.False(decision.Block);
        Assert.False(decision.ChallengeWeb);
    }

    [Fact]
    public void MissingToken_BlocksBrowserForm()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: true), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
        Assert.True(decision.ChallengeWeb);
    }

    [Fact]
    public void MissingToken_BlocksBrowserEvenWhenThePageHadNoCheck()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: true), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
        Assert.True(decision.ChallengeWeb);
    }

    [Fact]
    public void MissingToken_BlocksPasswordResetEvenWhenThePageHadNoCheck()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: false), AuthPathKind.PasswordReset, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
    }

    [Fact]
    public void RejectedToken_BlocksEvenWhenThePageHadNoCheck()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: true), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Rejected);
        Assert.True(decision.Block);
    }

    [Fact]
    public void NeverChallenges_UnknownClients()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: false), AuthPathKind.Password, ClientKind.Unknown, CaptchaCheck.Absent);
        Assert.False(decision.Block);
    }

    [Fact]
    public void UnknownClients_AreBlocked_WhenOptInIsOn()
    {
        var config = Ready(failOpen: false);
        config.CaptchaChallengeUnknown = true;
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Unknown, CaptchaCheck.Absent);
        Assert.True(decision.Block);
        Assert.False(decision.ChallengeWeb); // no widget is injected for non-browsers
    }

    [Fact]
    public void UnknownClients_AreAllowed_WhenOptInIsOn_AndTokenPassed()
    {
        var config = Ready(failOpen: false);
        config.CaptchaChallengeUnknown = true;
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Unknown, CaptchaCheck.Passed);
        Assert.False(decision.Block);
    }

    [Fact]
    public void UnknownClients_FailOpen_StillApplies_WhenOptInIsOn()
    {
        var config = Ready(failOpen: true);
        config.CaptchaChallengeUnknown = true;
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Unknown, CaptchaCheck.Unreachable);
        Assert.False(decision.Block);
    }

    [Fact]
    public void Apps_AreNeverChallenged_EvenWhenOptInIsOn()
    {
        var config = Ready(failOpen: false);
        config.CaptchaChallengeUnknown = true;
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.App, CaptchaCheck.Absent);
        Assert.False(decision.Block);
    }

    [Fact]
    public void NeedsVerification_IncludesUnknown_WhenOptInIsOn()
    {
        var config = Ready(failOpen: false);
        config.CaptchaChallengeUnknown = true;
        Assert.True(CaptchaPolicy.NeedsVerification(config, AuthPathKind.Password, ClientKind.Unknown));
    }

    [Fact]
    public void NeedsVerification_ExcludesUnknown_WhenOptInIsOff()
    {
        var config = Ready(failOpen: false);
        config.CaptchaChallengeUnknown = false;
        Assert.False(CaptchaPolicy.NeedsVerification(config, AuthPathKind.Password, ClientKind.Unknown));
    }

    [Fact]
    public void RejectedToken_BlocksBrowserForm()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: false), AuthPathKind.PasswordReset, ClientKind.Web, CaptchaCheck.Rejected);
        Assert.True(decision.Block);
    }

    [Fact]
    public void UnreachableGoogle_FailOpen_AllowsBrowser()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: true), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Unreachable);
        Assert.False(decision.Block);
    }

    [Fact]
    public void UnreachableGoogle_FailClosed_BlocksBrowser()
    {
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: false), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Unreachable);
        Assert.True(decision.Block);
    }

    [Fact]
    public void IncompleteKeys_DoNotBlock()
    {
        var config = Ready(failOpen: false);
        config.CaptchaSecret = string.Empty;
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Rejected);
        Assert.False(decision.Block);
    }

    [Fact]
    public void OtherProviders_DoNotBlock()
    {
        var config = Ready(failOpen: false);
        config.CaptchaProvider = "HCaptcha";
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Rejected);
        Assert.False(decision.Block);
    }

    [Fact]
    public void DirectApiRequest_WithoutCookie_StillBlocks()
    {
        // Simulates an attacker sending POST /Users/AuthenticateByName directly
        // without loading the login page first (no cookie, no token).
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: true), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
        Assert.True(decision.ChallengeWeb);
    }

    // --- Regression tests for the cookie-deletion bypass claim ---
    // A reviewer flagged CaptchaChallenge.WasIncluded() as a bypass risk.
    // That method was dead code and has been removed. These tests pin the
    // actual policy: a browser-classified client is blocked when the token
    // is missing, regardless of any cookie state. The policy never reads
    // cookies — it only reads the token check.

    [Fact]
    public void Regression_EmptyToken_BlocksBrowser_RegardlessOfCookie()
    {
        // An empty token string is treated as Absent by the middleware
        // (length 0 → no verification attempt). The policy blocks.
        var decision = CaptchaPolicy.Evaluate(Ready(failOpen: true), AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
        Assert.True(decision.ChallengeWeb);
    }

    [Fact]
    public void Regression_MissingCookie_DoesNotBypass_BrowserChallenge()
    {
        // The policy has no cookie parameter. A browser with no token is
        // blocked whether or not any cookie was ever set. This test exists
        // so that if someone reintroduces a cookie-based bypass, it fails.
        var config = Ready(failOpen: true);
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
    }

    [Fact]
    public void Regression_FailOpen_DoesNotApply_ToMissingToken()
    {
        // Fail-open applies only when the provider is unreachable
        // (CaptchaCheck.Unreachable). A missing token (Absent) must
        // block even when fail-open is on.
        var config = Ready(failOpen: true);
        var missingToken = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        var unreachable = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Unreachable);
        Assert.True(missingToken.Block);       // missing token → block
        Assert.False(unreachable.Block);        // provider down → fail-open allows
    }

    [Fact]
    public void Regression_RejectedToken_BlocksEvenWithFailOpen()
    {
        // A token that the provider explicitly rejected (not unreachable,
        // but rejected) must block even when fail-open is on. Fail-open is
        // for infrastructure failure, not for a bad token.
        var config = Ready(failOpen: true);
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Rejected);
        Assert.True(decision.Block);
    }

    /// <summary>
    /// Fail-open behavior is scoped to infrastructure failure only.
    /// The three security failures (Absent, Rejected) block regardless.
    /// Only Unreachable (the provider is down) respects the fail-open toggle.
    /// This test pins the distinction: a security denial never becomes an
    /// automatic allow, but an infrastructure failure may.
    /// </summary>
    [Fact]
    public void FailOpen_ScopedTo_InfrastructureFailure_Only()
    {
        var config = Ready(failOpen: true);

        // Security denials — block even with fail-open on
        Assert.True(CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent).Block);
        Assert.True(CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Rejected).Block);

        // Infrastructure failure — fail-open allows the request
        Assert.False(CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Unreachable).Block);

        // With fail-open off, infrastructure failure also blocks
        config.CaptchaFailOpen = false;
        Assert.True(CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Unreachable).Block);
    }

    [Fact]
    public void Turnstile_MissingToken_BlocksBrowserForm()
    {
        var config = Ready(failOpen: true);
        config.CaptchaProvider = "Turnstile";
        var decision = CaptchaPolicy.Evaluate(config, AuthPathKind.Password, ClientKind.Web, CaptchaCheck.Absent);
        Assert.True(decision.Block);
    }

    [Fact]
    public async Task TurnstileVerifier_PostsToCloudflare()
    {
        Uri? seen = null;
        var verifier = new TurnstileVerifier(Client(request =>
        {
            seen = request.RequestUri;
            return Json(HttpStatusCode.OK, "{\"success\":true,\"hostname\":\"media.example\"}");
        }));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, "media.example", CancellationToken.None);
        Assert.Equal(CaptchaCheck.Passed, check);
        Assert.Equal(TurnstileVerifier.VerifyUrl, seen?.ToString());
    }

    [Fact]
    public void LoginScript_UsesTurnstileWhenSelected()
    {
        var html = CaptchaLoginScript.Inject("<html><body></body></html>", SiteKey, "Turnstile");
        Assert.Contains("challenges.cloudflare.com/turnstile", html, StringComparison.Ordinal);
        Assert.Contains("var provider = \"turnstile\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verifier_AcceptsGoogleSuccess()
    {
        var verifier = new RecaptchaVerifier(Client(_ => Json(HttpStatusCode.OK, "{\"success\":true,\"hostname\":\"media.example\"}")));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, "media.example", CancellationToken.None);
        Assert.Equal(CaptchaCheck.Passed, check);
    }

    [Fact]
    public async Task Verifier_RejectsOtherHost()
    {
        var verifier = new RecaptchaVerifier(Client(_ => Json(HttpStatusCode.OK, "{\"success\":true,\"hostname\":\"evil.example\"}")));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, "media.example", CancellationToken.None);
        Assert.Equal(CaptchaCheck.Rejected, check);
    }

    [Fact]
    public async Task Verifier_RejectsNullHost()
    {
        var verifier = new RecaptchaVerifier(Client(_ => Json(HttpStatusCode.OK, "{\"success\":true,\"hostname\":\"evil.example\"}")));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, null, CancellationToken.None);
        Assert.Equal(CaptchaCheck.Rejected, check);
    }

    [Fact]
    public async Task Verifier_RejectsMissingHostname()
    {
        var verifier = new RecaptchaVerifier(Client(_ => Json(HttpStatusCode.OK, "{\"success\":true}")));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, "media.example", CancellationToken.None);
        Assert.Equal(CaptchaCheck.Rejected, check);
    }

    [Fact]
    public async Task Verifier_RejectsNullHostnameInResponse()
    {
        var verifier = new RecaptchaVerifier(Client(_ => Json(HttpStatusCode.OK, "{\"success\":true,\"hostname\":null}")));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, "media.example", CancellationToken.None);
        Assert.Equal(CaptchaCheck.Rejected, check);
    }

    [Fact]
    public async Task Verifier_TreatsHttpFailureAsUnreachable()
    {
        var verifier = new RecaptchaVerifier(Client(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        var check = await verifier.VerifyAsync(Secret, "token-value-ok", null, "media.example", CancellationToken.None);
        Assert.Equal(CaptchaCheck.Unreachable, check);
    }

    [Fact]
    public void LoginScript_InsertsCheckboxHook()
    {
        var html = CaptchaLoginScript.Inject("<html><body><div id=\"reactRoot\"></div></body></html>", SiteKey);
        Assert.Contains("txtManualPassword", html, StringComparison.Ordinal);
        Assert.Contains("forgotpassword", html, StringComparison.Ordinal);
        Assert.Contains("getClientRects", html, StringComparison.Ordinal);
        Assert.Contains("X-Jelly-Security-Captcha", html, StringComparison.Ordinal);
        Assert.Contains(SiteKey, html, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, html, StringComparison.Ordinal);
    }

    [Fact]
    public void GzipShell_StillReceivesGoogleCheck()
    {
        var result = RewriteCompressed(Gzip, "gzip", "ReCaptcha");
        Assert.True(result.Included);
        var html = Encoding.UTF8.GetString(result.Body);
        Assert.Contains("www.google.com/recaptcha", html, StringComparison.Ordinal);
        Assert.Contains("jelly-security-recaptcha", html, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, html, StringComparison.Ordinal);
    }

    [Fact]
    public void BrotliShell_StillReceivesTurnstileCheck()
    {
        var result = RewriteCompressed(Brotli, "br", "Turnstile");
        Assert.True(result.Included);
        var html = Encoding.UTF8.GetString(result.Body);
        Assert.Contains("challenges.cloudflare.com/turnstile", html, StringComparison.Ordinal);
        Assert.Contains("forgotpassword", html, StringComparison.Ordinal);
    }

    [Fact]
    public void DeflateShell_StillReceivesTheCheck()
    {
        var result = RewriteCompressed(Deflate, "deflate", "Google");
        Assert.True(result.Included);
        Assert.Contains("www.google.com/recaptcha", Encoding.UTF8.GetString(result.Body), StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownEncoding_LeavesTheBodyAlone()
    {
        var html = Encoding.UTF8.GetBytes("<html><body></body></html>");
        var result = CaptchaPageRewriter.Rewrite(200, "text/html", ["zstd"], html, SiteKey, "ReCaptcha");
        Assert.False(result.Included);
        Assert.Equal(html, result.Body);
    }

    [Fact]
    public void ScriptResponse_IsNotRewritten()
    {
        var result = CaptchaPageRewriter.Rewrite(200, "application/javascript", ["gzip"], Gzip("var playback = 1;"), SiteKey, "ReCaptcha");
        Assert.False(result.Included);
    }

    [Fact]
    public void LoginScript_IgnoresUnsafeSiteKey()
    {
        const string html = "<html><body></body></html>";
        Assert.Equal(html, CaptchaLoginScript.Inject(html, "<script>alert(1)</script>"));
    }

    private static CaptchaPageRewriter.Result RewriteCompressed(Func<string, byte[]> compress, string encoding, string provider)
    {
        const string html = "<!doctype html><html><body><div id=\"reactRoot\"></div></body></html>";
        return CaptchaPageRewriter.Rewrite(200, "text/html; charset=utf-8", [encoding], compress(html), SiteKey, provider);
    }

    private static byte[] Gzip(string text)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(text));
        }

        return output.ToArray();
    }

    private static byte[] Brotli(string text)
    {
        using var output = new MemoryStream();
        using (var brotli = new BrotliStream(output, CompressionLevel.Fastest, leaveOpen: true))
        {
            brotli.Write(Encoding.UTF8.GetBytes(text));
        }

        return output.ToArray();
    }

    private static byte[] Deflate(string text)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Fastest, leaveOpen: true))
        {
            deflate.Write(Encoding.UTF8.GetBytes(text));
        }

        return output.ToArray();
    }

    private static PluginConfiguration Ready(bool failOpen)
    {
        return new PluginConfiguration
        {
            CaptchaEnforceWeb = true,
            CaptchaFailOpen = failOpen,
            CaptchaProvider = "ReCaptcha",
            CaptchaSiteKey = SiteKey,
            CaptchaSecret = Secret
        };
    }

    private static HttpClient Client(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        return new HttpClient(new StubHandler(respond));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_respond(request));
        }
    }
}
