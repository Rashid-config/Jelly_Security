using Jellyfin.Plugin.JellySecurity.Configuration;

namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Sends the browser token to the configured provider only.
/// </summary>
public sealed class CaptchaVerifier
{
    private readonly RecaptchaVerifier _google;
    private readonly TurnstileVerifier _turnstile;

    public CaptchaVerifier()
        : this(new RecaptchaVerifier(), new TurnstileVerifier())
    {
    }

    public CaptchaVerifier(RecaptchaVerifier google, TurnstileVerifier turnstile)
    {
        _google = google;
        _turnstile = turnstile;
    }

    public Task<CaptchaCheck> VerifyAsync(
        PluginConfiguration config,
        string? token,
        string? remoteIp,
        string? expectedHost,
        CancellationToken cancellationToken)
    {
        if (CaptchaPolicy.IsTurnstile(config.CaptchaProvider))
        {
            return _turnstile.VerifyAsync(config.CaptchaSecret, token, remoteIp, expectedHost, cancellationToken);
        }

        return _google.VerifyAsync(config.CaptchaSecret, token, remoteIp, expectedHost, cancellationToken);
    }
}
