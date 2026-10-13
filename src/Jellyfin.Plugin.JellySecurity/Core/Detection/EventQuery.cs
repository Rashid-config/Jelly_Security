namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

public static class EventQuery
{
    public static IReadOnlyList<SecurityEvent> Filter(
        IEnumerable<SecurityEvent> source,
        string? outcome = null,
        string? address = null,
        string? username = null,
        string? kind = null,
        int take = 100)
    {
        var limit = Math.Clamp(take, 1, 500);
        return source
            .Where(e => string.IsNullOrWhiteSpace(outcome) || e.Outcome.Equals(outcome, StringComparison.OrdinalIgnoreCase))
            .Where(e => string.IsNullOrWhiteSpace(address) || string.Equals(e.Address, address.Trim(), StringComparison.OrdinalIgnoreCase))
            .Where(e => string.IsNullOrWhiteSpace(username) || string.Equals(e.Username, username.Trim(), StringComparison.OrdinalIgnoreCase))
            .Where(e => string.IsNullOrWhiteSpace(kind) || e.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(e => e.TimestampUtc)
            .Take(limit)
            .ToArray();
    }

    public static string ToCsv(IEnumerable<SecurityEvent> source)
    {
        var lines = new List<string> { "TimestampUtc,Kind,Outcome,Username,Address,Path,Trust,Enforced,Message" };
        foreach (var e in source)
        {
            lines.Add(string.Join(
                ',',
                TextSanitizer.CsvField(e.TimestampUtc.ToString("o")),
                TextSanitizer.CsvField(e.Kind),
                TextSanitizer.CsvField(e.Outcome),
                TextSanitizer.CsvField(e.Username),
                TextSanitizer.CsvField(e.Address),
                TextSanitizer.CsvField(e.Path),
                TextSanitizer.CsvField(e.Trust),
                e.Enforced ? "true" : "false",
                TextSanitizer.CsvField(e.Message)));
        }

        return string.Join('\n', lines);
    }
}
