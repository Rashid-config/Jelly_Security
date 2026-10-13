using Jellyfin.Plugin.JellySecurity.Core.Detection;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class TextSanitizerTests
{
    [Fact]
    public void StripsMarkup_AndNeutralizesCsvFormulas()
    {
        Assert.Equal(" script admin /script ", TextSanitizer.Display("<script>admin</script>"));
        Assert.Equal("'=cmd", TextSanitizer.Display("=cmd"));
        Assert.Contains("\"", TextSanitizer.CsvField("a,b"));
    }

    [Fact]
    public void HtmlEncode_EncodesAngleBrackets()
    {
        var result = TextSanitizer.HtmlEncode("user<script>alert(1)</script>");
        Assert.NotNull(result);
        Assert.DoesNotContain("<script>", result, StringComparison.Ordinal);
        Assert.Contains("alert", result, StringComparison.Ordinal);
    }

    [Fact]
    public void HtmlEncode_EncodesAmpersand()
    {
        var result = TextSanitizer.HtmlEncode("a&b");
        Assert.NotNull(result);
        Assert.DoesNotContain("&b", result, StringComparison.Ordinal);
    }

    [Fact]
    public void HtmlEncode_EncodesQuotes()
    {
        var result = TextSanitizer.HtmlEncode("\"hello\"");
        Assert.NotNull(result);
        Assert.DoesNotContain("\"", result, StringComparison.Ordinal);
    }

    [Fact]
    public void HtmlEncode_ReturnsNull_ForEmpty()
    {
        Assert.Null(TextSanitizer.HtmlEncode(null));
        Assert.Null(TextSanitizer.HtmlEncode(""));
        Assert.Null(TextSanitizer.HtmlEncode("   "));
    }
}
