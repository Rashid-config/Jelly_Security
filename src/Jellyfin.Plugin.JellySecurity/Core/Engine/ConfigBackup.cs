using System.Text.Json;
using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Detection;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Core.Engine;

public sealed class SecurityBackupDocument
{
    public int SchemaVersion { get; set; } = PluginConfiguration.CurrentSchemaVersion;

    public DateTimeOffset ExportedUtc { get; set; } = DateTimeOffset.UtcNow;

    public PluginConfiguration Configuration { get; set; } = new();

    public List<BanRecord> Bans { get; set; } = [];

    public bool SecretsRedacted { get; set; } = true;
}

public sealed record ImportPreview(bool Ok, string Message, IReadOnlyList<string> Changes, SecurityBackupDocument? Document);

/// <summary>
/// Export and preview import of plugin-owned settings. Jellyfin user accounts are never included.
/// </summary>
public static class ConfigBackup
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public static SecurityBackupDocument Export(PluginConfiguration config, IEnumerable<BanRecord> bans, bool includeSecrets)
    {
        var copy = Clone(config);
        var redacted = !includeSecrets;
        if (redacted)
        {
            copy.WebhookUrl = string.IsNullOrEmpty(copy.WebhookUrl) ? string.Empty : "(redacted)";
            copy.HoneypotUsername = string.IsNullOrEmpty(copy.HoneypotUsername) ? string.Empty : "(redacted)";
            copy.CaptchaSecret = string.IsNullOrEmpty(copy.CaptchaSecret) ? string.Empty : "(redacted)";
            copy.EdgeSharedKey = string.IsNullOrEmpty(copy.EdgeSharedKey) ? string.Empty : "(redacted)";
        }

        return new SecurityBackupDocument
        {
            SchemaVersion = PluginConfiguration.CurrentSchemaVersion,
            Configuration = copy,
            Bans = bans.Select(CloneBan).ToList(),
            SecretsRedacted = redacted
        };
    }

    public static ImportPreview Preview(string json, PluginConfiguration current)
    {
        SecurityBackupDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<SecurityBackupDocument>(json, Json);
        }
        catch (Exception ex)
        {
            return new ImportPreview(false, "Backup JSON is not valid: " + ex.Message, [], null);
        }

        if (document?.Configuration is null)
        {
            return new ImportPreview(false, "Backup does not contain configuration.", [], null);
        }

        if (document.SchemaVersion < 1 || document.SchemaVersion > PluginConfiguration.CurrentSchemaVersion)
        {
            return new ImportPreview(false, $"Unsupported schema_version {document.SchemaVersion}.", [], null);
        }

        var incoming = document.Configuration;
        var changes = new List<string>();
        if (incoming.Mode != current.Mode)
        {
            changes.Add($"Mode {current.Mode} → {incoming.Mode}");
        }

        if (incoming.AutomaticIpBans && !current.AutomaticIpBans)
        {
            changes.Add("Would enable automatic IP bans. Review proxy trust before applying.");
        }

        if (incoming.RestrictAdminNetworks && !current.RestrictAdminNetworks)
        {
            changes.Add("Would enable admin network restriction. The map does not cover every admin API.");
        }

        if (incoming.ProtectQuickConnect && !current.ProtectQuickConnect)
        {
            changes.Add("Would apply sign-in bans to Quick Connect.");
        }

        foreach (var ban in document.Bans)
        {
            var check = BanTargetValidator.Validate(ban.Target);
            if (!check.Ok)
            {
                return new ImportPreview(false, "A stored ban is invalid: " + check.Message, changes, null);
            }
        }

        // SSRF check: reject a webhook URL that points to a private or loopback
        // address. A redacted field keeps the current value on restore, so it
        // is not validated here.
        if (!document.SecretsRedacted
            && !string.IsNullOrWhiteSpace(incoming.WebhookUrl)
            && !WebhookPublisher.IsSafeUrl(incoming.WebhookUrl))
        {
            return new ImportPreview(false, "Webhook URL in the backup is not a safe public URL. Remove it or use a public HTTPS endpoint.", changes, null);
        }

        if (incoming.AutomaticIpBans && incoming.TrustForwardedFor && string.IsNullOrWhiteSpace(incoming.KnownProxies))
        {
            changes.Add("Would enable automatic IP bans with forwarded headers but no Known Proxies. Bans will stay off until proxies are configured.");
        }

        if (document.SecretsRedacted)
        {
            changes.Add("Secrets were redacted. Webhook URL and honeypot name will stay as they are now.");
        }

        return new ImportPreview(true, "Preview only. Nothing has been applied.", changes, document);
    }

    public static string Serialize(SecurityBackupDocument document)
    {
        return JsonSerializer.Serialize(document, Json);
    }

    private static PluginConfiguration Clone(PluginConfiguration config)
    {
        return JsonSerializer.Deserialize<PluginConfiguration>(JsonSerializer.Serialize(config, Json), Json)
            ?? new PluginConfiguration();
    }

    private static BanRecord CloneBan(BanRecord ban)
    {
        return new BanRecord
        {
            Id = ban.Id,
            Target = ban.Target,
            Kind = ban.Kind,
            Reason = TextSanitizer.Display(ban.Reason, 256) ?? ban.Reason,
            CreatedUtc = ban.CreatedUtc,
            ExpiresUtc = ban.ExpiresUtc,
            Strike = ban.Strike,
            CreatedBy = ban.CreatedBy
        };
    }
}
