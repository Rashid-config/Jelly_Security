using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.JellySecurity.Core.Detection;

/// <summary>
/// Optional outbound alert. Failures never affect sign-in. Secrets in the URL are not logged.
/// The URL is validated against SSRF: loopback, private, and link-local addresses are rejected.
/// Hostnames are DNS-resolved and every resolved address must be public. A connect callback
/// re-validates the resolved IP immediately before the socket opens to close the TOCTOU window.
/// </summary>
public sealed class WebhookPublisher
{
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        ConnectCallback = ValidateConnectAsync,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2)
    })
    { Timeout = TimeSpan.FromSeconds(3) };

    public void TryPublish(SecurityIncident incident, PluginConfiguration config, ILogger logger)
    {
        if (!config.WebhookEnabled || !IsSafeUrl(config.WebhookUrl))
        {
            return;
        }

        var url = config.WebhookUrl.Trim();
        var payload = new
        {
            incident.Id,
            incident.DetectorId,
            incident.Subject,
            incident.RiskBand,
            incident.RecommendedAction,
            incident.Count,
            incident.Explanation
        };

        _ = Task.Run(async () =>
        {
            try
            {
                using var response = await Client.PostAsJsonAsync(url, payload).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    logger.LogWarning("Webhook returned {Status}.", (int)response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Webhook delivery failed. Sign-in was not affected.");
            }
        });
    }

    /// <summary>
    /// Validates the webhook URL against SSRF. Rejects loopback, private,
    /// link-local, and other non-routable addresses. HTTPS is preferred but
    /// HTTP is allowed for local setups. Hostnames are DNS-resolved and every
    /// resolved address must be public. The connect callback re-checks the
    /// actual IP right before the socket opens to close the TOCTOU window.
    /// </summary>
    public static bool IsSafeUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
        {
            return false;
        }

        var host = uri.Host;
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        // If the host is an IP literal, reject if it is private/loopback/link-local.
        if (IPAddress.TryParse(host, out var address))
        {
            return IsPublicAddress(address);
        }

        // Hostnames: resolve and require every returned address to be public.
        // This catches cloud metadata endpoints (e.g. metadata.google.internal)
        // and internal names that resolve to private ranges. The connect
        // callback re-validates at connect time to close the TOCTOU window.
        try
        {
            var resolved = Dns.GetHostAddresses(host);
            if (resolved.Length == 0)
            {
                return false;
            }

            foreach (var ip in resolved)
            {
                if (!IsPublicAddress(ip))
                {
                    return false;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns true only for globally routable IPv4/IPv6 addresses.
    /// Rejects loopback, private, link-local, multicast, and unspecified.
    /// </summary>
    public static bool IsPublicAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (IPAddress.IsLoopback(address))
            {
                return false;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            var bytes = address.GetAddressBytes();

            // 0.0.0.0/8 — unspecified and "this network"
            if (bytes[0] == 0)
            {
                return false;
            }

            // 10.0.0.0/8 — private (RFC 1918)
            if (bytes[0] == 10)
            {
                return false;
            }

            // 172.16.0.0/12 — private (RFC 1918)
            if (bytes[0] == 172 && (bytes[1] & 0xF0) == 16)
            {
                return false;
            }

            // 192.168.0.0/16 — private (RFC 1918)
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return false;
            }

            // 169.254.0.0/16 — link-local (AWS/GCP metadata)
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return false;
            }

            // 127.0.0.0/8 — loopback
            if (bytes[0] == 127)
            {
                return false;
            }

            // 224.0.0.0/4 — multicast
            if ((bytes[0] & 0xF0) == 224)
            {
                return false;
            }

            // 240.0.0.0/4 — reserved
            if ((bytes[0] & 0xF0) == 240)
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (IPAddress.IsLoopback(address))
            {
                return false;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                return IsPublicAddress(address.MapToIPv4());
            }

            if (address.IsIPv6Multicast || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
            {
                return false;
            }

            // fc00::/7 — unique local (private)
            var bytes = address.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC)
            {
                return false;
            }

            // ::/128 — unspecified
            if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                return false;
            }

            return true;
        }

        return false;
    }

    /// <summary>
    /// Connect callback that re-validates the resolved IP immediately before the
    /// socket opens. This closes the TOCTOU window between IsSafeUrl (validation
    /// time) and the actual connection: a DNS rebinding attack that returned a
    /// public address at validation time but a private address at connect time
    /// is rejected here. The connection is aborted if the resolved IP is not
    /// a public address.
    /// </summary>
    private static async ValueTask<Stream> ValidateConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var port = context.DnsEndPoint.Port;

        IPAddress[] resolved;
        try
        {
            resolved = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            throw new HttpRequestException($"Webhook DNS resolution failed for {host}.");
        }

        IPAddress? chosen = null;
        foreach (var ip in resolved)
        {
            if (IsPublicAddress(ip))
            {
                chosen = ip;
                break;
            }
        }

        if (chosen is null)
        {
            throw new HttpRequestException($"Webhook host {host} resolved to a non-public address. SSRF protection refused the connection.");
        }

        var socket = new Socket(chosen.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        try
        {
            await socket.ConnectAsync(chosen, port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
