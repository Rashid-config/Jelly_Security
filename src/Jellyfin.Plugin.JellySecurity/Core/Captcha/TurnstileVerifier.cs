namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Checks a browser token with Cloudflare Turnstile siteverify.
/// The secret and token are not logged.
/// </summary>
public sealed class TurnstileVerifier
{
    public const string VerifyUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    private static readonly HttpClient DefaultClient = new() { Timeout = TimeSpan.FromSeconds(5) };

    private readonly HttpMessageInvoker _client;

    public TurnstileVerifier()
        : this(DefaultClient)
    {
    }

    public TurnstileVerifier(HttpMessageInvoker client)
    {
        _client = client;
    }

    public Task<CaptchaCheck> VerifyAsync(
        string secret,
        string? token,
        string? remoteIp,
        string? expectedHost,
        CancellationToken cancellationToken)
    {
        return RecaptchaVerifier.VerifyAtAsync(_client, VerifyUrl, secret, token, remoteIp, expectedHost, cancellationToken);
    }
}
