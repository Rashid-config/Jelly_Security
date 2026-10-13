using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Captcha;
using Jellyfin.Plugin.JellySecurity.Core.Edge;
using Jellyfin.Plugin.JellySecurity.Core.Networking;
using Jellyfin.Plugin.JellySecurity.Core.Sessions;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

/// <summary>
/// Inspects plugin settings and local store only. It does not claim to audit the whole server.
/// </summary>
public static class PostureAuditor
{
    public static IReadOnlyList<PostureFinding> Audit(PluginConfiguration config, IReadOnlyCollection<BanRecord> bans)
    {
        var findings = new List<PostureFinding>
        {
            new(
                "preauth-unproven",
                "Warning",
                "Jellyfin's lockout counter stays separate",
                "This plugin does not write InvalidLoginAttemptCount. A request it rejects is not a substitute for that counter.",
                false),
            new(
                "mode",
                config.Mode == ProtectionMode.MonitorOnly ? "Info" : "Warning",
                $"Protection mode is {config.Mode}",
                config.Mode == ProtectionMode.MonitorOnly
                    ? "Automatic IP bans stay off while Monitor Only is selected."
                    : "Enforcement modes still require a trusted client address and the enablement gate.",
                true)
        };

        if (config.TrustForwardedFor && CidrMatcher.Split(config.KnownProxies).Count == 0)
        {
            findings.Add(new PostureFinding(
                "proxy-unknown",
                "High",
                "X-Forwarded-For is trusted without Known Proxies",
                "Automatic IP decisions stay closed. A client can send a fake header.",
                true));
        }

        if (config.RestrictAdminNetworks && CidrMatcher.Split(config.AdminNetworks).Count == 0)
        {
            findings.Add(new PostureFinding(
                "admin-restriction-empty",
                "High",
                "Admin network restriction is on but no Admin Networks are set",
                "The engine ignores the restriction so the administrator cannot be locked out.",
                true));
        }
        else if (config.RestrictAdminNetworks)
        {
            findings.Add(new PostureFinding(
                "admin-restriction-partial",
                "Warning",
                "Admin network restriction coverage is partial",
                "Only a mapped set of user and system write routes is considered. Other admin APIs may remain reachable.",
                false));
        }

        if (!config.ProtectQuickConnect)
        {
            findings.Add(new PostureFinding(
                "quick-connect-observe",
                "Info",
                "Quick Connect is observed, not blocked",
                "Sign-in bans do not apply to Quick Connect until that option is enabled. TV and mobile clients use this path.",
                true));
        }

        if (config.WebhookEnabled && !string.IsNullOrWhiteSpace(config.WebhookUrl)
            && config.WebhookUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new PostureFinding(
                "webhook-http",
                "Warning",
                "Webhook uses HTTP",
                "Alert payloads may travel in clear text.",
                true));
        }

        if (bans.Any(b => BanTargetValidator.IsWideIpv6Prefix(b.Target)))
        {
            findings.Add(new PostureFinding(
                "wide-ipv6",
                "Warning",
                "A stored ban is wider than IPv6 /64",
                "Automatic prefix bans stay off. Review the manual CIDR before leaving it in place.",
                true));
        }

        findings.Add(new PostureFinding(
            "session-monitor",
            "Info",
            config.ObserveSessions ? "Session administration is observed" : "Session administration is not observed",
            "Playback progress and play commands are out of scope.",
            true));

        findings.Add(new PostureFinding(
            "session-watch",
            "Info",
            config.SessionWatchEnabled
                ? $"Session watch is on (alert at {SessionWatchPolicy.ConcurrentLimit(config.SessionWatchConcurrent)} concurrent sessions)"
                : "Session watch is off",
            "A successful sign-in from a new address, or too many concurrent sessions, raises an alert. The plugin does not log anyone out until an administrator uses the button. Sessions that are playing are left alone.",
            false));

        findings.Add(new PostureFinding(
            "captcha",
            "Info",
            CaptchaPostureTitle(config),
            "The checkbox is added to the browser login response by the plugin. Jellyfin web files on disk stay unchanged. Apps and unknown clients are never challenged. Fail-open applies only when the selected provider cannot be reached. Enabling this sends the challenge token and visitor address to that provider.",
            false));

        findings.Add(new PostureFinding(
            "password-delay",
            "Info",
            config.PasswordDelayEnabled
                ? $"Password delay is on ({config.PasswordDelayStepsSeconds}, ceiling {config.PasswordDelayCeilingSeconds}s)"
                : "Password delay is off",
            "Repeated password sign-in can wait 1s, then 3s, then 5s by default. Playback is never delayed. The option stays off until an administrator enables it.",
            false));

        findings.Add(new PostureFinding(
            "account-cooldown",
            "Info",
            config.AccountCooldownEnabled
                ? $"Account cooldown is on ({config.AccountCooldownMinutes} minutes)"
                : "Account cooldown is off",
            "A clear distributed spray can pause one username inside the plugin. The pause ends by itself. Jellyfin does not disable the account.",
            false));

        findings.Add(new PostureFinding(
            "lockout-watch",
            "Info",
            config.LockoutWatchEnabled
                ? $"Lockout watch is on (warn within {config.LockoutWatchRemaining} attempts of each account's own limit)"
                : "Lockout watch is off",
            "The plugin reads InvalidLoginAttemptCount and LoginAttemptsBeforeLockout. It does not reset or change either value. A limit of -1 or any non-positive limit means that account is not approaching lockout.",
            false));

        findings.Add(new PostureFinding(
            "honeypot",
            "Info",
            config.HoneypotInstantBan ? "Honeypot instant ban is on" : "Honeypot instant ban is off",
            "One use of a decoy name that matches no Jellyfin user can ban that verified IPv4 address. The option stays off until an administrator enables it. A name that belongs to a real user does not arm the ban.",
            false));

        findings.Add(new PostureFinding(
            "mfa",
            "Info",
            "MFA is not available",
            "No second factor is implemented. Jellyfin authentication is not replaced.",
            true));

        if (config.EdgeChannelEnabled)
        {
            findings.Add(new PostureFinding(
                "edge-channel",
                config.EdgeSharedKey.Length >= 16 ? "Warning" : "High",
                "Edge channel is enabled",
                "This exposes a limited blocklist to a shared-key caller. External threat lists are not applied automatically.",
                true));
        }

        var snippet = EdgeSnippetBuilder.Build(config, bans.Select(b => b.Target).ToArray());
        findings.Add(new PostureFinding(
            "edge-snippet",
            snippet.Enabled && !snippet.Ready ? "Warning" : "Info",
            snippet.Enabled ? $"Edge paste snippet is on ({snippet.Target})" : "Edge paste snippet is off",
            snippet.Enabled
                ? "The dashboard shows a snippet to paste into Nginx, Caddy, or Cloudflare. The plugin does not write those files. Only sign-in routes are limited."
                : "No proxy file is generated until an administrator enables the snippet.",
            false));

        if (!string.IsNullOrWhiteSpace(config.LocalGeoFile))
        {
            findings.Add(new PostureFinding(
                "local-geo",
                "Info",
                "A local geo file is configured",
                "Lookups stay on disk. Country data never raises a ban by itself.",
                true));
        }

        return findings;
    }

    private static string CaptchaPostureTitle(PluginConfiguration config)
    {
        if (!config.CaptchaEnforceWeb)
        {
            return "Browser challenge is off";
        }

        if (!CaptchaPolicy.IsReady(config))
        {
            return "Browser challenge is on but the site key or secret is missing";
        }

        return CaptchaPolicy.IsTurnstile(config.CaptchaProvider)
            ? "Cloudflare Turnstile is required on browser gateway forms"
            : "Google reCAPTCHA is required on browser gateway forms";
    }
}
