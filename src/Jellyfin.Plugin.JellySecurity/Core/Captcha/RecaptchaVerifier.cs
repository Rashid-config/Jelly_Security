using System.Net.Http.Headers;
using System.Text.Json;

namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Checks a browser token with Google reCAPTCHA siteverify.
/// The secret and token are not logged.
/// </summary>
public sealed class RecaptchaVerifier
{
    public const string VerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

    private static readonly HttpClient DefaultClient = new() { Timeout = TimeSpan.FromSeconds(5) };

    private readonly HttpMessageInvoker _client;

    public RecaptchaVerifier()
        : this(DefaultClient)
    {
    }

    public RecaptchaVerifier(HttpMessageInvoker client)
    {
        _client = client;
    }

    public async Task<CaptchaCheck> VerifyAsync(
        string secret,
        string? token,
        string? remoteIp,
        string? expectedHost,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return CaptchaCheck.Absent;
        }

        return await VerifyAtAsync(_client, VerifyUrl, secret, token, remoteIp, expectedHost, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<CaptchaCheck> VerifyAtAsync(
        HttpMessageInvoker client,
        string url,
        string secret,
        string? token,
        string? remoteIp,
        string? expectedHost,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return CaptchaCheck.Absent;
        }

        if (token.Length > 4096 || !RecaptchaKey.IsSecret(secret))
        {
            return CaptchaCheck.Rejected;
        }

        try
        {
            var fields = new Dictionary<string, string>
            {
                ["secret"] = secret.Trim(),
                ["response"] = token
            };
            if (!string.IsNullOrWhiteSpace(remoteIp))
            {
                fields["remoteip"] = remoteIp;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(fields)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return CaptchaCheck.Unreachable;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!document.RootElement.TryGetProperty("success", out var success)
                || success.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return CaptchaCheck.Unreachable;
            }

            if (!success.GetBoolean())
            {
                return CaptchaCheck.Rejected;
            }

            // Hostname binding is mandatory. Both Google reCAPTCHA and Cloudflare
            // Turnstile return a hostname field on a successful verification.
            // A missing hostname means the response is malformed, truncated, or
            // from a provider that did not bind the token to a host. In all of
            // those cases the token must not be trusted: treat absence as a
            // mismatch, not a pass. This prevents an attacker from replaying a
            // token issued for a different site when the response is partial.
            if (!document.RootElement.TryGetProperty("hostname", out var hostname)
                || hostname.ValueKind != JsonValueKind.String
                || !HostMatches(hostname.GetString(), expectedHost))
            {
                return CaptchaCheck.Rejected;
            }

            return CaptchaCheck.Passed;
        }
        catch (Exception)
        {
            return CaptchaCheck.Unreachable;
        }
    }

    public static bool HostMatches(string? reportedHost, string? expectedHost)
    {
        // Both must be present. A missing expected host or reported host
        // is treated as a mismatch, not a pass. This prevents an attacker
        // from reusing a token from a different site when headers are absent.
        if (string.IsNullOrWhiteSpace(expectedHost) || string.IsNullOrWhiteSpace(reportedHost))
        {
            return false;
        }

        return string.Equals(reportedHost.Trim(), expectedHost.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
