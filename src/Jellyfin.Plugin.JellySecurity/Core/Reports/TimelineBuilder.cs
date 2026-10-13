using System.Net;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Reports;

/// <summary>
/// One step in an attack story: a sign-in attempt, a detected pattern, or a ban applied.
/// </summary>
public sealed class TimelineStep
{
    public DateTimeOffset TimestampUtc { get; set; }

    /// <summary>
    /// "Attempt" for a sign-in event, "Scan" for an API-scan event, "Pattern" for a detected incident, "Ban" for an enforcement action.
    /// </summary>
    public string Type { get; set; } = string.Empty;

    public string Outcome { get; set; } = string.Empty;

    public string? Username { get; set; }

    public string? Address { get; set; }

    public string? RiskBand { get; set; }

    public string Message { get; set; } = string.Empty;

    public bool Enforced { get; set; }
}

/// <summary>
/// A correlated attack story: all events, patterns, and bans linked to one subject
/// (an IP address or a username), within a time window.
/// </summary>
public sealed class AttackStory
{
    /// <summary>
    /// The grouping key: an IP address or a username.
    /// </summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    /// "Address" or "Username" — what the story is grouped by.
    /// </summary>
    public string GroupBy { get; set; } = string.Empty;

    public DateTimeOffset FirstUtc { get; set; }

    public DateTimeOffset LastUtc { get; set; }

    /// <summary>
    /// Total events in this story.
    /// </summary>
    public int AttemptCount { get; set; }

    /// <summary>
    /// How many of those attempts failed (Jellyfin rejected).
    /// </summary>
    public int FailedCount { get; set; }

    /// <summary>
    /// How many were blocked by the plugin.
    /// </summary>
    public int BlockedCount { get; set; }

    /// <summary>
    /// How many distinct usernames were tried (for address-grouped stories).
    /// </summary>
    public int DistinctUsernames { get; set; }

    /// <summary>
    /// How many distinct addresses were seen (for username-grouped stories).
    /// </summary>
    public int DistinctAddresses { get; set; }

    /// <summary>
    /// The highest risk band seen in this story.
    /// </summary>
    public string? HighestRiskBand { get; set; }

    /// <summary>
    /// Whether a ban was applied during this story.
    /// </summary>
    public bool WasBanned { get; set; }

    /// <summary>
    /// The ban kind, if any ("manual", "automatic", "progressive", "geo", "prefix").
    /// </summary>
    public string? BanKind { get; set; }

    /// <summary>
    /// The detected patterns that fired during this story.
    /// </summary>
    public List<string> Detectors { get; set; } = [];

    /// <summary>
    /// The chronological steps: attempts, pattern detections, and ban actions.
    /// </summary>
    public List<TimelineStep> Steps { get; set; } = [];

    /// <summary>
    /// How long the attack lasted, from first to last event.
    /// </summary>
    public string Duration => LastUtc > FirstUtc
        ? FormatDuration(LastUtc - FirstUtc)
        : "instant";

    private static string FormatDuration(TimeSpan span)
    {
        if (span.TotalSeconds < 60) { return $"{(int)span.TotalSeconds}s"; }
        if (span.TotalMinutes < 60) { return $"{(int)span.TotalMinutes}m {span.Seconds}s"; }
        if (span.TotalHours < 24) { return $"{(int)span.TotalHours}h {(int)span.Minutes}m"; }
        return $"{(int)span.TotalDays}d {(int)span.Hours}h";
    }
}

/// <summary>
/// Builds attack stories by correlating sign-in events, incidents, and bans.
/// Groups by address by default, because most attacks come from one source IP.
/// </summary>
public static class TimelineBuilder
{
    private static readonly Dictionary<string, int> RiskRank = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Low"] = 0,
        ["Moderate"] = 1,
        ["Medium"] = 1,
        ["High"] = 2,
        ["Critical"] = 3
    };

    /// <summary>
    /// Build attack stories from events, incidents, and bans. Only stories with
    /// at least one failed or blocked attempt are included — successful sign-ins
    /// from known addresses are not "attacks."
    /// </summary>
    public static IReadOnlyList<AttackStory> Build(
        IReadOnlyList<SecurityEvent> events,
        IReadOnlyList<SecurityIncident> incidents,
        IReadOnlyCollection<BanRecord> bans,
        int maxStories = 50,
        int maxStepsPerStory = 100)
    {
        var storyLimit = Math.Clamp(maxStories, 1, 200);
        var stepLimit = Math.Clamp(maxStepsPerStory, 10, 500);

        // Group events by address. Each address that has at least one
        // Failed or Blocked event becomes a story.
        var byAddress = events
            .Where(e => !string.IsNullOrWhiteSpace(e.Address))
            .GroupBy(e => e.Address!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new
            {
                Address = g.Key,
                Events = g.OrderBy(e => e.TimestampUtc).ToList(),
                HasAttack = g.Any(e => e.Outcome is "Failed" or "Blocked")
            })
            .Where(g => g.HasAttack)
            .ToList();

        // Build a ban lookup by address (exact match or CIDR match).
        var banList = bans.ToList();

        // Build an incident lookup by subject (address or username).
        var incidentsBySubject = incidents
            .GroupBy(i => i.Subject, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var stories = new List<AttackStory>();
        foreach (var group in byAddress)
        {
            var evs = group.Events;
            var first = evs.First().TimestampUtc;
            var last = evs.Last().TimestampUtc;

            var story = new AttackStory
            {
                Subject = group.Address,
                GroupBy = "Address",
                FirstUtc = first,
                LastUtc = last,
                AttemptCount = evs.Count,
                FailedCount = evs.Count(e => e.Outcome == "Failed"),
                BlockedCount = evs.Count(e => e.Outcome == "Blocked"),
                DistinctUsernames = evs.Where(e => !string.IsNullOrWhiteSpace(e.Username))
                    .Select(e => e.Username!).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                HighestRiskBand = HighestRisk(evs),
                WasBanned = false
            };

            // Check for a ban matching this address.
            foreach (var ban in banList)
            {
                if (BanMatchesAddress(ban, group.Address))
                {
                    story.WasBanned = true;
                    story.BanKind = ban.Kind.ToString();
                    break;
                }
            }

            // Add detector names from incidents that mention this address.
            if (incidentsBySubject.TryGetValue(group.Address, out var matchingIncidents))
            {
                story.Detectors = matchingIncidents
                    .Select(i => i.DetectorId)
                    .Distinct()
                    .ToList();
            }

            // Build the chronological steps.
            var steps = new List<TimelineStep>();
            foreach (var e in evs)
            {
                steps.Add(new TimelineStep
                {
                    TimestampUtc = e.TimestampUtc,
                    Type = e.Kind == "Reconnaissance" ? "Scan" : "Attempt",
                    Outcome = e.Outcome,
                    Username = e.Username,
                    Address = e.Address,
                    RiskBand = e.RiskBand,
                    Message = e.Message,
                    Enforced = e.Enforced
                });
            }

            // Add ban steps.
            foreach (var ban in banList)
            {
                if (BanMatchesAddress(ban, group.Address))
                {
                    steps.Add(new TimelineStep
                    {
                        TimestampUtc = ban.CreatedUtc,
                        Type = "Ban",
                        Outcome = "Blocked",
                        Username = null,
                        Address = group.Address,
                        RiskBand = null,
                        Message = $"{ban.Kind} ban applied: {ban.Reason}",
                        Enforced = true
                    });
                }
            }

            story.Steps = steps.OrderBy(s => s.TimestampUtc).Take(stepLimit).ToList();
            stories.Add(story);
        }

        // Sort by most active (most attempts) then most recent.
        return stories
            .OrderByDescending(s => s.AttemptCount)
            .ThenByDescending(s => s.LastUtc)
            .Take(storyLimit)
            .ToList();
    }

    private static string? HighestRisk(IReadOnlyList<SecurityEvent> events)
    {
        string? highest = null;
        var highestRank = -1;
        foreach (var e in events)
        {
            if (string.IsNullOrWhiteSpace(e.RiskBand)) { continue; }
            if (RiskRank.TryGetValue(e.RiskBand, out var rank) && rank > highestRank)
            {
                highestRank = rank;
                highest = e.RiskBand;
            }
        }
        return highest;
    }

    private static bool BanMatchesAddress(BanRecord ban, string address)
    {
        if (string.IsNullOrWhiteSpace(ban.Target)) { return false; }

        // Exact match (manual single-IP bans, automatic bans).
        if (ban.Target.Equals(address, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // CIDR match (CIDR bans, automatic prefix bans).
        if (ban.Kind is BanKind.Cidr or BanKind.AutomaticPrefix)
        {
            return Core.Networking.CidrMatcher.Matches(address, ban.Target);
        }

        return false;
    }
}
