namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Allowlist of Jellyfin API paths that reveal server structure and are worth
/// watching for reconnaissance (enumeration) traffic. Playback, images,
/// downloads, websockets, and static web assets are never included — a request
/// that is not on this list is never counted, so streaming and normal client
/// activity cannot trip the watch.
/// A path counts when its first segment matches a surface root and the rest of
/// the path does not descend into per-item endpoints (item images, streams,
/// subtitles) that legitimate clients hammer constantly.
/// </summary>
public static class ReconPathClassifier
{
    /// <summary>
    /// Collection and info endpoints a scanner probes to map the server.
    /// </summary>
    private static readonly HashSet<string> SurfaceRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        "Users", "Items", "Shows", "Artists", "Albums", "Songs",
        "Genres", "MusicGenres", "Studios", "Persons", "Years",
        "Library", "System", "Sessions", "Plugins", "ScheduledTasks",
        "ActivityLog", "AuditLog", "Dashboard", "DisplayPreferences",
        "UserViews", "NextUp", "Suggestions", "Resume", "LiveTv",
        "Channels", "Playlists", "Collections", "Localization",
        "Environment", "Startup", "Branding", "Packages", "QuickConnect",
        "Trailers", "ApiDocs", "api-docs", "swagger", "openapi",
        "Auth", "SyncPlay", "InstalledPlugins", "UserSettings"
    };

    /// <summary>
    /// Exact subpath segments that indicate per-item heavy traffic — posters,
    /// streams, downloads, playback state. A real client loading a library
    /// grid produces hundreds of these and must never count. Exact match (not
    /// substring) so surface names like "MediaFolders" are unaffected.
    /// </summary>
    private static readonly HashSet<string> DeepSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "Image", "Images", "Stream", "Streams", "Download", "File", "Files",
        "Subtitle", "Subtitles", "PlaybackInfo", "Transcoding", "HLS",
        "ThemeSongs", "ThemeVideos", "SpecialFeatures", "Chapters", "Lyrics",
        "Attachments", "CriticReviews", "Ancestors", "Intros", "MediaSegments",
        "MediaSources", "Playing", "Progress", "PlayedItems", "FavoriteItems",
        "Similar", "InstantMix", "Refresh", "DeleteInfo", "Trailers",
        "Persons", "Studios", "Artists", "Genres", "Overview",
        "ExternalUrls", "MetadataEditor", "ContentOptions", "Rating",
        "RemoteSearch", "Resume", "UserData"
    };

    /// <summary>
    /// Maximum path depth (segments) that can still count as a surface probe.
    /// Deeper paths are per-item endpoints.
    /// </summary>
    private const int MaxDepth = 4;

    public static bool IsApiSurface(string? path)
    {
        if (string.IsNullOrEmpty(path) || path[0] != '/')
        {
            return false;
        }

        // Strip query string if the caller passed a full URL-ish value.
        var span = path.AsSpan();
        var query = span.IndexOf('?');
        if (query >= 0)
        {
            span = span[..query];
        }

        var firstSlash = span[1..].IndexOf('/');
        var firstSegment = firstSlash < 0 ? span[1..] : span[1..(firstSlash + 1)];
        if (firstSegment.IsEmpty || !SurfaceRoots.Contains(firstSegment.ToString()))
        {
            return false;
        }

        var remainder = firstSlash < 0 ? ReadOnlySpan<char>.Empty : span[(firstSlash + 1)..];
        var depth = remainder.IsEmpty ? 1 : CountSegments(remainder);

        if (depth > MaxDepth)
        {
            return false;
        }

        // Any GUID-looking segment means a per-item endpoint
        // (e.g. /Items/{id}/Similar) — those are normal client traffic.
        // Excluded keywords cover /Images, /Stream, /Download, etc.
        var rest = remainder;
        while (!rest.IsEmpty)
        {
            var nextSlash = rest[1..].IndexOf('/');
            var segment = nextSlash < 0 ? rest[1..] : rest[1..(nextSlash + 1)];
            if (IsGuidLike(segment) || IsDeepSegment(segment))
            {
                return false;
            }

            rest = nextSlash < 0 ? ReadOnlySpan<char>.Empty : rest[(nextSlash + 1)..];
        }

        return true;
    }

    private static int CountSegments(ReadOnlySpan<char> path)
    {
        // path starts with '/'. Count non-empty segments.
        var count = 0;
        var i = 0;
        while (i < path.Length)
        {
            if (path[i] == '/')
            {
                i++;
                continue;
            }

            count++;
            var next = path[i..].IndexOf('/');
            i = next < 0 ? path.Length : i + next;
        }

        return count;
    }

    private static bool IsGuidLike(ReadOnlySpan<char> segment)
    {
        // Jellyfin ids are 32-hex or dashed GUIDs. A long hex-ish segment
        // is treated as an id even when the format is unexpected.
        if (segment.Length < 8)
        {
            return false;
        }

        if (segment.Length >= 32)
        {
            var hex = 0;
            foreach (var c in segment)
            {
                if (char.IsAsciiHexDigit(c) || c == '-')
                {
                    hex++;
                }
            }

            if (hex >= segment.Length - 1)
            {
                return true;
            }
        }

        return Guid.TryParse(segment, out _);
    }

    private static bool IsDeepSegment(ReadOnlySpan<char> segment)
    {
        return DeepSegments.Contains(segment.ToString());
    }
}
