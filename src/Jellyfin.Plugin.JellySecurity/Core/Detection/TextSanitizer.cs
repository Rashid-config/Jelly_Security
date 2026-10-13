using System.Text;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Keeps usernames and reasons safe for the event page and CSV export.
/// </summary>
public static class TextSanitizer
{
    public static string? Display(string? value, int maxLength = 128)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim()
            .Replace('<', ' ')
            .Replace('>', ' ')
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ');

        if (text.StartsWith('=') || text.StartsWith('+') || text.StartsWith('-') || text.StartsWith('@'))
        {
            text = "'" + text;
        }

        if (text.Length > maxLength)
        {
            text = text[..maxLength];
        }

        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    /// <summary>
    /// HTML-encodes a value for safe display in web pages.
    /// Use this instead of Display() when output goes into HTML.
    /// Encodes ampersand, angle brackets, quotes, and apostrophes.
    /// </summary>
    public static string? HtmlEncode(string? value, int maxLength = 128)
    {
        var display = Display(value, maxLength);
        if (display is null)
        {
            return null;
        }

        var builder = new StringBuilder(display.Length + 16);
        foreach (var ch in display)
        {
            switch (ch)
            {
                case '&':
                    builder.Append('&').Append('a').Append('m').Append('p').Append(';');
                    break;
                case '<':
                    builder.Append('&').Append('l').Append('t').Append(';');
                    break;
                case '>':
                    builder.Append('&').Append('g').Append('t').Append(';');
                    break;
                case '"':
                    builder.Append('&').Append('q').Append('u').Append('o').Append('t').Append(';');
                    break;
                case '\'':
                    builder.Append('&').Append('#').Append('x').Append('2').Append('7').Append(';');
                    break;
                default:
                    builder.Append(ch);
                    break;
            }
        }

        return builder.ToString();
    }

    public static string CsvField(string? value)
    {
        var text = Display(value, 256) ?? string.Empty;
        if (text.Contains('"') || text.Contains(',') || text.Contains('\n'))
        {
            return "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        }

        return text;
    }
}
