using Jellyfin.Plugin.JellySecurity.Configuration;
using Jellyfin.Plugin.JellySecurity.Core.Engine;
using Jellyfin.Plugin.JellySecurity.Core.Policies;

namespace Jellyfin.Plugin.JellySecurity.Tests;

public class ConfigBackupTests
{
    [Fact]
    public void Export_RedactsSecrets_ByDefault()
    {
        var config = new PluginConfiguration
        {
            WebhookUrl = "https://203.0.113.5/hook?token=secret",
            HoneypotUsername = "trap"
        };
        var document = ConfigBackup.Export(config, [], false);
        Assert.Equal("(redacted)", document.Configuration.WebhookUrl);
        Assert.Equal("(redacted)", document.Configuration.HoneypotUsername);
        Assert.True(document.SecretsRedacted);
    }

    [Fact]
    public void Preview_Rejects_InvalidBan()
    {
        var document = ConfigBackup.Export(new PluginConfiguration(), [new BanRecord { Target = "0.0.0.0/0" }], false);
        var json = ConfigBackup.Serialize(document);
        var preview = ConfigBackup.Preview(json, new PluginConfiguration());
        Assert.False(preview.Ok);
    }

    [Fact]
    public void Preview_Warns_WhenEnablingAutomaticBans()
    {
        var incoming = ConfigBackup.Export(new PluginConfiguration { AutomaticIpBans = true, Mode = ProtectionMode.Balanced }, [], false);
        var preview = ConfigBackup.Preview(ConfigBackup.Serialize(incoming), new PluginConfiguration());
        Assert.True(preview.Ok);
        Assert.Contains(preview.Changes, c => c.Contains("automatic IP", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Preview_Rejects_SsrfWebhookUrl()
    {
        var config = new PluginConfiguration
        {
            WebhookEnabled = true,
            WebhookUrl = "http://169.254.169.254/latest/meta-data/"
        };
        var document = ConfigBackup.Export(config, [], true);
        var json = ConfigBackup.Serialize(document);
        // Verify the webhook URL survived the export round-trip
        Assert.Contains("169.254.169.254", json, StringComparison.OrdinalIgnoreCase);
        var preview = ConfigBackup.Preview(json, new PluginConfiguration());
        Assert.False(preview.Ok);
        Assert.Contains("not a safe", preview.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Preview_Accepts_RedactedWebhookUrl()
    {
        // A redacted backup keeps the current webhook on restore, so the
        // "(redacted)" placeholder must not trip the SSRF validation.
        var document = ConfigBackup.Export(new PluginConfiguration
        {
            WebhookEnabled = true,
            WebhookUrl = "https://203.0.113.5/hook"
        }, [], includeSecrets: false);
        var preview = ConfigBackup.Preview(ConfigBackup.Serialize(document), new PluginConfiguration());
        Assert.True(preview.Ok);
    }

    [Fact]
    public void Preview_Accepts_PublicWebhookUrl()
    {
        // IP literal: no DNS needed, keeps the suite offline-safe.
        var incoming = ConfigBackup.Export(new PluginConfiguration
        {
            WebhookEnabled = true,
            WebhookUrl = "https://203.0.113.5/hook"
        }, [], true);
        var preview = ConfigBackup.Preview(ConfigBackup.Serialize(incoming), new PluginConfiguration());
        Assert.True(preview.Ok);
    }
}
