using Jellyfin.Plugin.JellySecurity.Configuration;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.JellySecurity.Core.Networking;

/// <summary>
/// Resolves the client address only when the connection path is trustworthy.
/// </summary>
public sealed class ProxyTrustValidator
{
    public ClientIdentity Resolve(HttpContext context, PluginConfiguration config)
    {
        var remote = context.Connection.RemoteIpAddress;
        var remoteText = remote is null ? string.Empty : IpNormalizer.Normalize(remote);

        if (string.IsNullOrEmpty(remoteText))
        {
            return new ClientIdentity(null, string.Empty, SourceTrust.Unknown, "No remote socket address.", false);
        }

        var forwardedPresent = context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded)
            && !string.IsNullOrWhiteSpace(forwarded.ToString());

        var remoteIsKnownProxy = CidrMatcher.Matches(remoteText, config.KnownProxies);

        if (config.TrustForwardedFor)
        {
            if (!remoteIsKnownProxy)
            {
                return new ClientIdentity(
                    remoteText,
                    remoteText,
                    SourceTrust.Unknown,
                    "X-Forwarded-For is enabled but the socket address is not a known proxy. Automatic IP bans stay off.",
                    false);
            }

            if (!forwardedPresent)
            {
                return new ClientIdentity(
                    remoteText,
                    remoteText,
                    SourceTrust.Warning,
                    "The request came from a known proxy without X-Forwarded-For.",
                    false);
            }

            var hops = forwarded.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (hops.Length == 0)
            {
                return new ClientIdentity(
                    remoteText,
                    remoteText,
                    SourceTrust.Warning,
                    "X-Forwarded-For was present but contained no usable hops.",
                    true,
                    0,
                    false);
            }

            // Walk the chain right-to-left. The rightmost hop is the closest
            // to us. Skip hops that belong to known proxies (trusted
            // intermediaries). The first non-proxy address from the right is
            // the actual client. This prevents an attacker from injecting a
            // fake address at the left of the chain when a proxy appends
            // (rather than overwrites) X-Forwarded-For. If any non-proxy hop
            // remains to the left of the chosen client, the chain is
            // ambiguous and treated as Warning so automatic bans stay off.
            string? clientIp = null;
            var ambiguous = false;
            for (var i = hops.Length - 1; i >= 0; i--)
            {
                var hop = IpNormalizer.Normalize(hops[i]);
                if (hop is null)
                {
                    ambiguous = true;
                    continue;
                }

                if (CidrMatcher.Matches(hop, config.KnownProxies))
                {
                    continue;
                }

                clientIp ??= hop;
                for (var j = i - 1; j >= 0; j--)
                {
                    var left = IpNormalizer.Normalize(hops[j]);
                    if (left is null)
                    {
                        ambiguous = true;
                        break;
                    }

                    if (!CidrMatcher.Matches(left, config.KnownProxies))
                    {
                        ambiguous = true;
                        break;
                    }
                }

                break;
            }

            if (clientIp is null)
            {
                return new ClientIdentity(
                    remoteText,
                    remoteText,
                    SourceTrust.Warning,
                    "X-Forwarded-For did not contain a usable non-proxy address.",
                    true,
                    hops.Length,
                    ambiguous);
            }

            return new ClientIdentity(
                clientIp,
                remoteText,
                ambiguous ? SourceTrust.Warning : SourceTrust.Verified,
                ambiguous
                    ? "X-Forwarded-For has a non-proxy hop to the left of the client. The rightmost non-proxy address is used but treated as ambiguous."
                    : "Client address taken from X-Forwarded-For because the socket belongs to a known proxy.",
                true,
                hops.Length,
                ambiguous);
        }

        if (forwardedPresent && !remoteIsKnownProxy)
        {
            return new ClientIdentity(
                remoteText,
                remoteText,
                SourceTrust.Warning,
                "X-Forwarded-For was present but ignored because TrustForwardedFor is off.",
                false);
        }

        return new ClientIdentity(
            remoteText,
            remoteText,
            SourceTrust.Verified,
            "Using the TCP remote address.",
            false);
    }

    public bool AllowsAutomaticIpBans(PluginConfiguration config, ClientIdentity identity)
    {
        if (!config.AutomaticIpBans)
        {
            return false;
        }

        if (config.Mode == ProtectionMode.MonitorOnly)
        {
            return false;
        }

        if (config.TrustForwardedFor && CidrMatcher.Split(config.KnownProxies).Count == 0)
        {
            return false;
        }

        return identity.Trust == SourceTrust.Verified && identity.Address is not null;
    }
}
