using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Integration;

namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Browser challenge for gateway forms. Google reCAPTCHA v2 or Cloudflare Turnstile.
/// TV apps are never challenged. Unknown clients are challenged only when an admin opts in.
/// </summary>
public static class CaptchaPolicy
{
    public static bool IsGoogle(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return false;
        }

        return provider.Equals("ReCaptcha", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("reCAPTCHA", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("Google", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("GoogleReCaptcha", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsTurnstile(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return false;
        }

        return provider.Equals("Turnstile", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("Cloudflare", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("CloudflareTurnstile", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsReady(PluginConfiguration config)
    {
        return config.CaptchaEnforceWeb
            && (IsGoogle(config.CaptchaProvider) || IsTurnstile(config.CaptchaProvider))
            && RecaptchaKey.IsSiteKey(config.CaptchaSiteKey)
            && RecaptchaKey.IsSecret(config.CaptchaSecret);
    }

    public static bool NeedsVerification(PluginConfiguration config, AuthPathKind kind, ClientKind client)
    {
        if (!IsReady(config) || kind is not (AuthPathKind.Password or AuthPathKind.PasswordReset))
        {
            return false;
        }

        return client == ClientKind.Web
            || (config.CaptchaChallengeUnknown && client == ClientKind.Unknown);
    }

    public static CaptchaDecision Evaluate(
        PluginConfiguration config,
        AuthPathKind kind,
        ClientKind client,
        CaptchaCheck check)
    {
        if (!config.CaptchaEnforceWeb || kind is not (AuthPathKind.Password or AuthPathKind.PasswordReset))
        {
            return new CaptchaDecision(false, false, "CAPTCHA enforcement is off or this is not a browser gateway form.");
        }

        // Recognized TV/mobile apps can never render a challenge widget, so they are always exempt.
        if (client == ClientKind.App)
        {
            return new CaptchaDecision(false, false, "CAPTCHA is not applied to apps.");
        }

        // Unknown clients (no recognizable User-Agent) are exempt unless an admin opts in.
        // A bot that spoofs a TV app User-Agent is classified as App and still bypasses; this
        // option closes the simpler path of sending no recognizable UA at all.
        if (client == ClientKind.Unknown && !config.CaptchaChallengeUnknown)
        {
            return new CaptchaDecision(false, false, "CAPTCHA is not applied to unknown clients.");
        }

        if (!IsReady(config))
        {
            return new CaptchaDecision(false, false, "Challenge keys are incomplete, so the gateway form is not blocked.");
        }

        if (check == CaptchaCheck.Passed)
        {
            return new CaptchaDecision(true, false, "Browser challenge accepted.");
        }

        if (check == CaptchaCheck.Unreachable && config.CaptchaFailOpen)
        {
            return new CaptchaDecision(true, false, "The challenge provider could not be reached. Fail-open keeps the browser form available.");
        }

        // A missing token always blocks when enforcement is on for a web browser.
        // The previous behavior allowed bypass when the page had not included the check
        // (no cookie), but that is exactly the path an automated tool takes: it sends
        // a direct API request without loading the login page, so no cookie is set.
        // Removing this bypass closes that hole. The fail-open option still applies
        // when the provider is unreachable (CaptchaCheck.Unreachable).
        //
        // For Unknown clients, ChallengeWeb stays false: no widget is injected because
        // the client is not a browser. The request is simply blocked until a valid
        // token is supplied, which a non-browser bot cannot obtain.
        var challengeWeb = client == ClientKind.Web;
        var reason = challengeWeb
            ? "The browser gateway form requires a completed challenge."
            : "Unrecognized client must supply a valid challenge token.";
        return new CaptchaDecision(challengeWeb, true, reason);
    }
}
