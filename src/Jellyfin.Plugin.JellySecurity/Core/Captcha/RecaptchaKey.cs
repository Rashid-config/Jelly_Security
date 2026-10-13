namespace Jellyfin.Plugin.JellySecurity.Core.Captcha;

public static class RecaptchaKey
{
    public static bool IsSiteKey(string? value) => IsKey(value);

    public static bool IsSecret(string? value) => IsKey(value);

    private static bool IsKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var text = value.Trim();
        if (text.Length is < 20 or > 200)
        {
            return false;
        }

        foreach (var ch in text)
        {
            if (ch is not ((>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }
}
