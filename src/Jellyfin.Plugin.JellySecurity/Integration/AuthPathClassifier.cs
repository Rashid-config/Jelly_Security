using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Integration;

/// <summary>
/// Maps Jellyfin 12.2 authentication routes. Playback paths are never classified.
/// </summary>
public static class AuthPathClassifier
{
    public static AuthPathKind Classify(HttpRequest request)
    {
        var path = request.Path.Value;
        if (string.IsNullOrEmpty(path))
        {
            return AuthPathKind.None;
        }

        if (Matches(path, "/Users/AuthenticateByName") && HttpMethods.IsPost(request.Method))
        {
            return AuthPathKind.Password;
        }

        if (Matches(path, "/Users/AuthenticateWithQuickConnect") && HttpMethods.IsPost(request.Method))
        {
            return AuthPathKind.QuickConnect;
        }

        if (IsUserAuthenticate(path) && HttpMethods.IsPost(request.Method))
        {
            return AuthPathKind.Password;
        }

        if (Matches(path, "/Users/ForgotPassword") && HttpMethods.IsPost(request.Method))
        {
            return AuthPathKind.PasswordReset;
        }

        if ((Matches(path, "/QuickConnect/Initiate") || Matches(path, "/QuickConnect/Authorize"))
            && HttpMethods.IsPost(request.Method))
        {
            return AuthPathKind.QuickConnect;
        }

        if (IsKnownAdminMutation(request.Method, path))
        {
            return AuthPathKind.Admin;
        }

        if (IsSessionAdministration(request.Method, path))
        {
            return AuthPathKind.Session;
        }

        return AuthPathKind.None;
    }

    /// <summary>
    /// Partial map of Jellyfin 12.2 write routes that change users or server policy.
    /// Playback, library, and session progress are never included.
    /// The map covers a known set of user and system write routes. It does not cover every admin API.
    /// </summary>
    public static bool IsKnownAdminMutation(string method, string path)
    {
        if (HttpMethods.IsPost(method))
        {
            return Matches(path, "/System/Configuration")
                || Matches(path, "/System/Configuration/Partial")
                || Matches(path, "/Users/New")
                || IsUserSubPath(path, "Policy")
                || EndsWithUsersCollection(path);
        }

        return HttpMethods.IsDelete(method) && IsUserRoot(path);
    }

    public static bool IsSessionAdministration(string method, string path)
    {
        if (!path.Contains("/Sessions", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (path.Contains("/Playing", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/Progress", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/Message", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/Command", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/Viewing", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return HttpMethods.IsDelete(method)
            || (HttpMethods.IsGet(method) && Matches(path, "/Sessions"));
    }

    private static bool EndsWithUsersCollection(string path)
    {
        return path.EndsWith("/Users", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/Users/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUserRoot(string path)
    {
        const string marker = "/Users/";
        var index = path.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        var rest = path[(index + marker.Length)..].Trim('/');
        return Guid.TryParse(rest, out _);
    }

    private static bool IsUserSubPath(string path, string name)
    {
        const string marker = "/Users/";
        var index = path.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        var rest = path[(index + marker.Length)..];
        var slash = rest.IndexOf('/');
        return slash > 0
            && Guid.TryParse(rest[..slash], out _)
            && rest[(slash + 1)..].Equals(name, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsPasswordSignInPath(string? path)
    {
        return !string.IsNullOrEmpty(path)
            && (Matches(path, "/Users/AuthenticateByName") || IsUserAuthenticate(path));
    }

    /// <summary>
    /// True for paths that carry credentials: password sign-in, Quick Connect,
    /// and password reset. Other observed routes (admin mutations, session
    /// administration) are generic authorization denials and must not feed the
    /// sign-in failure counter that drives automatic bans.
    /// </summary>
    public static bool IsCredentialPath(string? path)
    {
        return !string.IsNullOrEmpty(path)
            && (IsPasswordSignInPath(path)
                || Matches(path, "/Users/AuthenticateWithQuickConnect")
                || Matches(path, "/QuickConnect/Initiate")
                || Matches(path, "/QuickConnect/Authorize")
                || Matches(path, "/Users/ForgotPassword"));
    }

    private static bool Matches(string path, string suffix)
    {
        // Jellyfin API routes are root-level. Match if the path equals the
        // suffix, or starts with the suffix followed by a path separator or
        // query string. This rejects /foo/Users/AuthenticateByName while
        // accepting /Users/AuthenticateByName and /Users/AuthenticateByName?x=1.
        return path.Equals(suffix, StringComparison.OrdinalIgnoreCase)
            || (path.StartsWith(suffix, StringComparison.OrdinalIgnoreCase)
                && path.Length > suffix.Length
                && (path[suffix.Length] == '/' || path[suffix.Length] == '?'));
    }

    private static bool IsUserAuthenticate(string path)
    {
        const string marker = "/Users/";
        var index = path.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        var rest = path[(index + marker.Length)..];
        var slash = rest.IndexOf('/');
        if (slash <= 0)
        {
            return false;
        }

        return rest[(slash + 1)..].Equals("Authenticate", StringComparison.OrdinalIgnoreCase)
            && Guid.TryParse(rest[..slash], out _);
    }
}
