using System.Text;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Edge;

public sealed record EdgeSnippetResult(
    bool Enabled,
    bool Ready,
    string Target,
    bool BlocklistIncluded,
    string Note,
    string Text,
    int DenyCount);

/// <summary>
/// Builds a paste snippet for a proxy the administrator already runs.
/// Nothing here writes Nginx, Caddy, or Cloudflare files.
/// </summary>
public static class EdgeSnippetBuilder
{
    public const string DefaultUpstream = "127.0.0.1:8096";

    public static EdgeSnippetResult Build(PluginConfiguration config, IReadOnlyList<string>? bans)
    {
        if (!config.EdgeSnippetEnabled)
        {
            return new EdgeSnippetResult(false, false, string.Empty, false, "Edge snippet is off. No proxy file was written.", string.Empty, 0);
        }

        var target = NormalizeTarget(config.EdgeSnippetTarget);
        if (target.Length == 0)
        {
            return new EdgeSnippetResult(true, false, string.Empty, false, "Unknown edge target.", string.Empty, 0);
        }

        var needsUpstream = target is "Nginx" or "Caddy";
        string upstream;
        if (!needsUpstream)
        {
            upstream = string.Empty;
        }
        else if (!TryUpstream(config.EdgeSnippetUpstream, out upstream))
        {
            return new EdgeSnippetResult(true, false, target, false, "Upstream is not a host and port.", string.Empty, 0);
        }

        var perMinute = PerMinute(config.EdgeSnippetAuthPerMinute);
        var burst = Burst(config.EdgeSnippetBurst);
        var deny = EdgeDenyText.Lines(bans);
        var include = WantsBlocklist(config, out var key);
        var text = target switch
        {
            "Caddy" => Caddy(upstream, perMinute, include, key, deny),
            "Cloudflare" => Cloudflare(perMinute, include, key, deny),
            _ => Nginx(upstream, perMinute, burst, include, key, deny)
        };

        var note = include
            ? "Ready to paste. The plugin did not write the proxy file."
            : config.EdgeSnippetIncludeBlocklist
                ? "Ready to paste. Blocklist section omitted because the edge channel is off or the shared key is not a safe token."
                : "Ready to paste. The plugin did not write the proxy file.";

        return new EdgeSnippetResult(true, true, target, include, note, text, deny.Count);
    }

    public static string NormalizeTarget(string? target)
    {
        var value = target?.Trim() ?? string.Empty;
        if (value.Length == 0 || value.Equals("Nginx", StringComparison.OrdinalIgnoreCase))
        {
            return "Nginx";
        }

        if (value.Equals("Caddy", StringComparison.OrdinalIgnoreCase))
        {
            return "Caddy";
        }

        if (value.Equals("Cloudflare", StringComparison.OrdinalIgnoreCase))
        {
            return "Cloudflare";
        }

        return string.Empty;
    }

    public static int PerMinute(int configured)
    {
        var value = configured <= 0 ? 30 : configured;
        return Math.Clamp(value, 1, 600);
    }

    public static int Burst(int configured)
    {
        var value = configured < 0 ? 10 : configured;
        return Math.Clamp(value, 0, 100);
    }

    public static bool TryUpstream(string? value, out string hostPort)
    {
        var text = string.IsNullOrWhiteSpace(value) ? DefaultUpstream : value.Trim();
        hostPort = text;
        if (text.Length > 200 || text.Contains('\\') || text.Contains('"') || text.Contains('\''))
        {
            return false;
        }

        if (text.StartsWith('['))
        {
            var end = text.IndexOf(']');
            if (end <= 1 || end + 2 >= text.Length || text[end + 1] != ':')
            {
                return false;
            }

            return IsHexOrColon(text[1..end]) && IsPort(text[(end + 2)..]);
        }

        var colon = text.LastIndexOf(':');
        if (colon <= 0 || colon == text.Length - 1)
        {
            return false;
        }

        var host = text[..colon];
        return IsPort(text[(colon + 1)..])
            && Regex.IsMatch(host, "^[A-Za-z0-9.-]+$")
            && !host.Contains("..", StringComparison.Ordinal);
    }

    private static bool WantsBlocklist(PluginConfiguration config, out string key)
    {
        key = string.Empty;
        if (!config.EdgeSnippetIncludeBlocklist || !config.EdgeChannelEnabled)
        {
            return false;
        }

        var candidate = config.EdgeSharedKey?.Trim() ?? string.Empty;
        if (!Regex.IsMatch(candidate, "^[A-Za-z0-9_-]{16,200}$"))
        {
            return false;
        }

        key = candidate;
        return true;
    }

    private static string Nginx(string upstream, int perMinute, int burst, bool include, string key, IReadOnlyList<string> deny)
    {
        var limit = burst > 0
            ? $"        limit_req zone=jelly_security_auth burst={burst} nodelay;"
            : "        limit_req zone=jelly_security_auth nodelay;";
        var builder = new StringBuilder();
        builder.AppendLine("# Jelly Security edge paste. The plugin did not write this file.");
        builder.AppendLine("# IMPORTANT: This is an ADDITION, not a replacement. Keep your existing server block,");
        builder.AppendLine("# your domain, your SSL certificates, and your playback proxy_pass lines as they are.");
        builder.AppendLine("# Back up your nginx config first: cp /etc/nginx/sites-available/jellyfin /etc/nginx/sites-available/jellyfin.bak");
        builder.AppendLine("# Sign-in routes only. Playback URLs are not listed and are not limited.");
        builder.AppendLine("# Fast repeated sign-in is rejected here, before the request reaches Jellyfin.");
        builder.AppendLine("# This is not a volumetric flood defense. TV apps use these sign-in routes too.");
        builder.AppendLine("# The plugin trusts X-Forwarded-For only after Known Proxies contains this proxy.");
        builder.AppendLine();
        builder.AppendLine("# --- part 1: http context ---");
        builder.AppendLine("# Paste this ONCE inside the http { } block in nginx.conf (not inside server { }).");
        builder.AppendLine("# If you already have a limit_req_zone with this name, skip this part.");
        builder.AppendLine($"limit_req_zone $binary_remote_addr zone=jelly_security_auth:10m rate={perMinute}r/m;");
        builder.AppendLine();
        builder.AppendLine("# --- part 2: server context ---");
        builder.AppendLine("# Paste these location blocks INSIDE your existing Jellyfin server { } block.");
        builder.AppendLine("# They only add rate-limiting to sign-in routes. Your existing proxy_pass,");
        builder.AppendLine("# SSL, domain, and playback configuration stays untouched.");
        foreach (var path in new[]
        {
            "/Users/AuthenticateByName",
            "/Users/ForgotPassword",
            "/Users/AuthenticateWithQuickConnect",
            "/QuickConnect/Initiate",
            "/QuickConnect/Authorize"
        })
        {
            AppendNginxLocation(builder, $"= {path}", upstream, limit);
        }

        AppendNginxLocation(builder, "~ \"^/Users/[0-9A-Fa-f-]+/Authenticate$\"", upstream, limit);
        AppendBlocklist(builder, "Nginx", upstream, include, key, deny);
        builder.AppendLine();
        builder.AppendLine("# After pasting: nginx -t  (test the config)");
        builder.AppendLine("# If it passes: systemctl reload nginx");
        builder.AppendLine("# If it fails: restore from the .bak file and try again.");
        return builder.ToString().TrimEnd() + Environment.NewLine;
    }

    private static void AppendNginxLocation(StringBuilder builder, string pattern, string upstream, string limit)
    {
        builder.AppendLine($"location {pattern} {{");
        builder.AppendLine(limit);
        builder.AppendLine("        limit_req_status 429;");
        builder.AppendLine($"        proxy_pass http://{upstream};");
        builder.AppendLine("        proxy_set_header Host $host;");
        builder.AppendLine("        proxy_set_header X-Real-IP $remote_addr;");
        builder.AppendLine("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
        builder.AppendLine("        proxy_set_header X-Forwarded-Proto $scheme;");
        builder.AppendLine("}");
        builder.AppendLine();
    }

    private static string Caddy(string upstream, int perMinute, bool include, string key, IReadOnlyList<string> deny)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Jelly Security edge paste. The plugin did not write this file.");
        builder.AppendLine("# IMPORTANT: This is an ADDITION, not a replacement. Keep your existing site block,");
        builder.AppendLine("# your domain, your TLS certificates, and your reverse_proxy lines as they are.");
        builder.AppendLine("# Back up your Caddyfile first: cp Caddyfile Caddyfile.bak");
        builder.AppendLine("# Requires github.com/mholt/caddy-ratelimit. The plugin does not install that module.");
        builder.AppendLine("# Paste inside the site block that already reverse_proxies Jellyfin. Do not replace the playback proxy.");
        builder.AppendLine("# Sign-in POST routes only. Playback URLs are not matched.");
        builder.AppendLine("# Fast repeated sign-in is rejected here, before the request reaches Jellyfin.");
        builder.AppendLine("# This is not a volumetric flood defense. TV apps use these sign-in routes too.");
        builder.AppendLine();
        builder.AppendLine("rate_limit {");
        builder.AppendLine("	zone jelly_security_auth {");
        builder.AppendLine("		match {");
        builder.AppendLine("			method POST");
        builder.AppendLine("			path /Users/AuthenticateByName /Users/ForgotPassword /Users/AuthenticateWithQuickConnect /QuickConnect/Initiate /QuickConnect/Authorize /Users/*/Authenticate");
        builder.AppendLine("		}");
        builder.AppendLine("		key {remote_host}");
        builder.AppendLine($"		events {perMinute}");
        builder.AppendLine("		window 1m");
        builder.AppendLine("	}");
        builder.AppendLine("}");
        builder.AppendLine();
        builder.AppendLine($"# Upstream already expected by this site: {upstream}");
        AppendBlocklist(builder, "Caddy", upstream, include, key, deny);
        builder.AppendLine();
        builder.AppendLine("# After pasting: caddy validate  (test the config)");
        builder.AppendLine("# If it passes: systemctl reload caddy");
        builder.AppendLine("# If it fails: restore from Caddyfile.bak and try again.");
        return builder.ToString().TrimEnd() + Environment.NewLine;
    }

    private static string Cloudflare(int perMinute, bool include, string key, IReadOnlyList<string> deny)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Jelly Security edge paste. The plugin did not write this to Cloudflare and does not call the Cloudflare API.");
        builder.AppendLine("# IMPORTANT: This is an ADDITION, not a replacement. Keep your existing DNS records,");
        builder.AppendLine("# your SSL/TLS mode, your page rules, and your other WAF rules as they are.");
        builder.AppendLine("# Dashboard: Security > WAF > Rate limiting rules > Create rule.");
        builder.AppendLine("# Do not enable a site-wide bot challenge. That breaks TV and mobile apps.");
        builder.AppendLine("# Match expression, POST sign-in only. Playback URLs are not included.");
        builder.AppendLine("# Fast repeated sign-in is rejected at Cloudflare, before the request reaches Jellyfin.");
        builder.AppendLine("# This is not a volumetric flood defense by itself.");
        builder.AppendLine();
        builder.AppendLine("(http.request.method eq \"POST\" and (http.request.uri.path eq \"/Users/AuthenticateByName\" or http.request.uri.path eq \"/Users/ForgotPassword\" or http.request.uri.path eq \"/Users/AuthenticateWithQuickConnect\" or http.request.uri.path eq \"/QuickConnect/Initiate\" or http.request.uri.path eq \"/QuickConnect/Authorize\" or (starts_with(http.request.uri.path, \"/Users/\") and ends_with(http.request.uri.path, \"/Authenticate\"))))");
        builder.AppendLine();
        builder.AppendLine($"# When rate exceeds: {perMinute} requests per 1 minute");
        builder.AppendLine("# Counting characteristic: IP");
        builder.AppendLine("# Action: Block");
        builder.AppendLine("# Raise the number in the plugin and paste again if one household address is too small.");
        AppendBlocklist(builder, "Cloudflare", string.Empty, include, key, deny);
        builder.AppendLine();
        builder.AppendLine("# No reload needed — Cloudflare applies the rule immediately.");
        builder.AppendLine("# To remove: delete the rule in the same dashboard page.");
        return builder.ToString().TrimEnd() + Environment.NewLine;
    }

    private static void AppendBlocklist(StringBuilder builder, string target, string upstream, bool include, string key, IReadOnlyList<string> deny)
    {
        builder.AppendLine();
        if (!include)
        {
            builder.AppendLine("# Active ban export is not in this paste. Turn it on only after the edge channel has a long key made of letters, digits, '_' or '-'.");
            return;
        }

        var fetch = string.IsNullOrEmpty(upstream)
            ? "/JellySecurity/edge/deny.txt?format=" + target.ToLowerInvariant()
            : $"http://{upstream}/JellySecurity/edge/deny.txt?format={target.ToLowerInvariant()}";
        builder.AppendLine("# Ban export below is a snapshot. The plugin does not refresh it and does not reload the proxy.");
        builder.AppendLine("# The shared key authenticates the edge route. Jellyfin may still require its own authentication on that path.");
        builder.AppendLine($"# curl -fsS -H \"X-Jelly-Security-Edge-Key: {key}\" \"{fetch}\"");
        if (deny.Count == 0)
        {
            builder.AppendLine("# No active bans to paste.");
            return;
        }

        var shown = deny.Take(200).ToArray();
        if (target == "Nginx")
        {
            builder.AppendLine("# Uncomment the include only after that curl has written a file and nginx -t succeeds.");
            builder.AppendLine("# include /etc/nginx/jelly-security-deny.conf;");
            foreach (var item in shown)
            {
                builder.AppendLine($"# deny {item};");
            }
        }
        else if (target == "Caddy")
        {
            builder.AppendLine("@jelly_security_banned {");
            builder.AppendLine("	remote_ip " + string.Join(' ', shown));
            builder.AppendLine("}");
            builder.AppendLine("handle @jelly_security_banned {");
            builder.AppendLine("	respond 403");
            builder.AppendLine("}");
        }
        else
        {
            builder.AppendLine("# Paste these addresses into a Cloudflare IP list yourself. The plugin does not create that list.");
            foreach (var item in shown)
            {
                builder.AppendLine(item);
            }
        }

        if (deny.Count > shown.Length)
        {
            builder.AppendLine("# Further addresses are only on the deny endpoint.");
        }
    }

    private static bool IsPort(string value)
    {
        return ushort.TryParse(value, out var port) && port > 0;
    }

    private static bool IsHexOrColon(string value)
    {
        return value.Length > 0 && value.All(ch => (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') || ch == ':');
    }
}

public static class EdgeDenyText
{
    public static bool TryFormat(string? format, IReadOnlyList<string>? bans, out string text)
    {
        var kind = (format ?? "nginx").Trim();
        if (kind.Length == 0)
        {
            kind = "nginx";
        }

        if (kind.Equals("nginx", StringComparison.OrdinalIgnoreCase))
        {
            text = Nginx(Lines(bans));
            return true;
        }

        if (kind.Equals("caddy", StringComparison.OrdinalIgnoreCase))
        {
            text = string.Join('\n', Lines(bans));
            return true;
        }

        if (kind.Equals("cloudflare", StringComparison.OrdinalIgnoreCase))
        {
            text = string.Join('\n', Lines(bans));
            return true;
        }

        text = string.Empty;
        return false;
    }

    public static IReadOnlyList<string> Lines(IReadOnlyList<string>? bans)
    {
        if (bans is null || bans.Count == 0)
        {
            return [];
        }

        var lines = new List<string>();
        foreach (var ban in bans)
        {
            var check = BanTargetValidator.Validate(ban);
            if (!check.Ok || string.IsNullOrEmpty(check.Normalized) || !IsSafeToken(check.Normalized))
            {
                continue;
            }

            lines.Add(check.Normalized);
        }

        return lines;
    }

    private static string Nginx(IReadOnlyList<string> lines)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Jelly Security deny list. The plugin did not write this file.");
        if (lines.Count == 0)
        {
            builder.AppendLine("# no active bans");
        }

        foreach (var line in lines)
        {
            builder.AppendLine($"deny {line};");
        }

        return builder.ToString();
    }

    private static bool IsSafeToken(string value)
    {
        return value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or ':' or '/');
    }
}
