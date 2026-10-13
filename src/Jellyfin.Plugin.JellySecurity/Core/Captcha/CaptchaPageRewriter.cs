using System.IO.Compression;
using System.Text;

namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

/// <summary>
/// Puts the check into the sign-in shell, including a body that arrived compressed.
/// Jellyfin web files on disk are not edited.
/// </summary>
public static class CaptchaPageRewriter
{
    public const int MaxDocumentBytes = 1_500_000;

    public readonly record struct Result(bool Included, byte[] Body);

    public static Result Rewrite(
        int statusCode,
        string? contentType,
        IEnumerable<string>? contentEncodings,
        byte[] body,
        string? siteKey,
        string? provider)
    {
        if (!TryReadHtml(statusCode, contentType, contentEncodings, body, out var html))
        {
            return new Result(false, body);
        }

        var injected = CaptchaLoginScript.Inject(html, siteKey, provider);
        if (!injected.Contains("jelly-security-recaptcha", StringComparison.Ordinal))
        {
            return new Result(false, body);
        }

        return new Result(true, Encoding.UTF8.GetBytes(injected));
    }

    private static bool TryReadHtml(
        int statusCode,
        string? contentType,
        IEnumerable<string>? contentEncodings,
        byte[] body,
        out string html)
    {
        html = string.Empty;
        if (statusCode != 200 || body.Length is 0 or > MaxDocumentBytes)
        {
            return false;
        }

        if (string.IsNullOrEmpty(contentType) || !contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        byte[] plain;
        try
        {
            plain = Inflate(body, contentEncodings);
        }
        catch (Exception)
        {
            return false;
        }

        if (plain.Length is 0 or > MaxDocumentBytes || !LooksLikeMarkup(plain))
        {
            return false;
        }

        using var reader = new StreamReader(new MemoryStream(plain), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        html = reader.ReadToEnd();
        return html.Length > 0;
    }

    private static byte[] Inflate(byte[] body, IEnumerable<string>? contentEncodings)
    {
        var layers = new List<string>();
        if (contentEncodings is not null)
        {
            foreach (var value in contentEncodings)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!part.Equals("identity", StringComparison.OrdinalIgnoreCase))
                    {
                        layers.Add(part);
                    }
                }
            }
        }

        var current = body;
        for (var i = layers.Count - 1; i >= 0; i--)
        {
            current = layers[i].ToLowerInvariant() switch
            {
                "gzip" or "x-gzip" => ReadLimited(current, stream => new GZipStream(stream, CompressionMode.Decompress)),
                "br" => ReadLimited(current, stream => new BrotliStream(stream, CompressionMode.Decompress)),
                "deflate" => ReadLimited(current, stream => new DeflateStream(stream, CompressionMode.Decompress)),
                _ => throw new InvalidDataException("Unsupported content encoding.")
            };
        }

        return current;
    }

    private static byte[] ReadLimited(byte[] compressed, Func<Stream, Stream> open)
    {
        using var input = new MemoryStream(compressed);
        using var decoder = open(input);
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = decoder.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxDocumentBytes)
            {
                throw new InvalidDataException("Decompressed document is too large.");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private static bool LooksLikeMarkup(byte[] body)
    {
        var index = 0;
        if (body.Length >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF)
        {
            index = 3;
        }

        while (index < body.Length && body[index] is (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t')
        {
            index++;
        }

        return index < body.Length && body[index] == (byte)'<';
    }
}
