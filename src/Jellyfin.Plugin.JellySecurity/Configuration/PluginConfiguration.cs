using Jellyfin.Plugin.JellySecurity.Core.Geo;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.JellySecurity.Configuration;

/// <summary>
/// Plugin settings stored by Jellyfin. Automatic IP bans stay off until an admin enables them after a proxy check.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    public PluginConfiguration()
    {
        Mode = ProtectionMode.MonitorOnly;
        AutomaticIpBans = false;
        AutomaticIpv6PrefixBan = false;
        ApplyManualBans = true;
        FailuresBeforeBan = 10;
        FailureWindowMinutes = 5;
        FirstBanMinutes = 5;
        ProgressiveBanMinutes = "5,15,60,1440";
        EscalationResetDays = 7;
        DistributedIpCount = 5;
        DistributedFailures = 8;
        DistributedWindowSeconds = 60;
        PasswordSprayNames = 8;
        PasswordSprayWindowMinutes = 5;
        TrustForwardedFor = false;
        KnownProxies = string.Empty;
        TrustedNetworks = string.Empty;
        AdminNetworks = string.Empty;
        MonitoringNetworks = string.Empty;
        EventRetentionDays = 30;
        MaxEvents = 20000;
        HoneypotUsername = string.Empty;
        HoneypotInstantBan = false;
        HoneypotBanMinutes = 60;
        CounterCapacity = 10000;
        EnableBruteForceDetector = true;
        EnableDistributedDetector = true;
        EnablePasswordSprayDetector = true;
        EnableEnumerationDetector = true;
        EnableHoneypotDetector = true;
        EnableAdminTargetDetector = true;
        AdministrativeUsernames = string.Empty;
        AlertCooldownMinutes = 15;
        WebhookEnabled = false;
        WebhookUrl = string.Empty;
        RestrictAdminNetworks = false;
        ProtectQuickConnect = false;
        ObserveSessions = false;
        CaptchaProvider = "None";
        CaptchaSiteKey = string.Empty;
        CaptchaSecret = string.Empty;
        CaptchaEnforceWeb = false;
        CaptchaFailOpen = true;
        CaptchaChallengeUnknown = false;
        StrictDeviceFingerprint = false;
        PasswordDelayEnabled = false;
        PasswordDelayStepsSeconds = "1,3,5";
        PasswordDelayCeilingSeconds = 5;
        PasswordDelayWindowMinutes = 15;
        PasswordDelayAfterFailures = 1;
        PasswordDelayRequireVerifiedAddress = true;
        PasswordDelaySkipPrivilegedNetworks = true;
        AccountCooldownEnabled = false;
        AccountCooldownMinutes = 15;
        AccountCooldownDistinctIps = 5;
        AccountCooldownFailures = 8;
        AccountCooldownWindowMinutes = 15;
        AccountCooldownSkipPrivilegedNetworks = true;
        LockoutWatchEnabled = false;
        LockoutWatchRemaining = 5;
        LockoutWatchCooldownMinutes = 60;
        SessionWatchEnabled = false;
        SessionWatchConcurrent = 4;
        SessionWatchCooldownMinutes = 60;
        SessionWatchRequireVerifiedAddress = true;
        SessionWatchSkipPrivilegedNetworks = true;
        EdgeChannelEnabled = false;
        EdgeSharedKey = string.Empty;
        EdgeRestrictToTrustedPeers = true;
        EdgeSnippetEnabled = false;
        EdgeSnippetTarget = "Nginx";
        EdgeSnippetUpstream = "127.0.0.1:8096";
        EdgeSnippetAuthPerMinute = 30;
        EdgeSnippetBurst = 10;
        EdgeSnippetIncludeBlocklist = false;
        LocalGeoFile = string.Empty;
        GeoBlocks = [];
        ReconWatchEnabled = false;
        ReconEnforce = false;
        ReconWindowMinutes = 5;
        ReconFailedThreshold = 30;
        ReconUnauthThreshold = 120;
        ReconDistinctPathMin = 15;
        ReconCooldownMinutes = 10;
        SchemaVersion = CurrentSchemaVersion;
    }

    /// <summary>
    /// The schema version this build writes and understands. Backups and saved
    /// configurations stamped at or below this version load; anything higher
    /// came from a newer plugin build and is refused.
    /// </summary>
    public const int CurrentSchemaVersion = 8;

    public ProtectionMode Mode { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the engine may create temporary IP bans.
    /// Off until proxy identity is trusted and an admin turns it on.
    /// </summary>
    public bool AutomaticIpBans { get; set; }

    /// <summary>
    /// When true, automatic bans for IPv6 addresses ban the containing /64 prefix instead of
    /// being skipped entirely. A /64 is the smallest prefix an end-user network typically
    /// receives, so this blocks the whole customer subnet without nailing down one address.
    /// Off by default: prefix bans are broader than single-address bans.
    /// </summary>
    public bool AutomaticIpv6PrefixBan { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether bans added by an administrator are enforced.
    /// </summary>
    public bool ApplyManualBans { get; set; }

    public int FailuresBeforeBan { get; set; }

    public int FailureWindowMinutes { get; set; }

    public int FirstBanMinutes { get; set; }

    public string ProgressiveBanMinutes { get; set; }

    public int EscalationResetDays { get; set; }

    public int DistributedIpCount { get; set; }

    public int DistributedFailures { get; set; }

    public int DistributedWindowSeconds { get; set; }

    public int PasswordSprayNames { get; set; }

    public int PasswordSprayWindowMinutes { get; set; }

    public bool TrustForwardedFor { get; set; }

    public string KnownProxies { get; set; }

    public string TrustedNetworks { get; set; }

    public string AdminNetworks { get; set; }

    public string MonitoringNetworks { get; set; }

    public int EventRetentionDays { get; set; }

    public int MaxEvents { get; set; }

    /// <summary>
    /// Optional decoy username. A match is a signal only; instant IP ban stays off.
    /// </summary>
    public string HoneypotUsername { get; set; }

    /// <summary>
    /// When true, one use of the decoy name bans that verified IPv4 address.
    /// Idle when the name matches a Jellyfin user. Off until an administrator enables it.
    /// </summary>
    public bool HoneypotInstantBan { get; set; }

    public int HoneypotBanMinutes { get; set; }

    public int CounterCapacity { get; set; }

    public bool EnableBruteForceDetector { get; set; }

    public bool EnableDistributedDetector { get; set; }

    public bool EnablePasswordSprayDetector { get; set; }

    public bool EnableEnumerationDetector { get; set; }

    public bool EnableHoneypotDetector { get; set; }

    public bool EnableAdminTargetDetector { get; set; }

    /// <summary>
    /// Usernames the administrator listed as privileged. The plugin does not infer this from the word admin.
    /// </summary>
    public string AdministrativeUsernames { get; set; }

    public int AlertCooldownMinutes { get; set; }

    public bool WebhookEnabled { get; set; }

    public string WebhookUrl { get; set; }

    /// <summary>
    /// Partial map only. Off by default. Ignored when Admin Networks is empty.
    /// </summary>
    public bool RestrictAdminNetworks { get; set; }

    /// <summary>
    /// When false, Quick Connect is observed but sign-in bans are not applied to those routes.
    /// </summary>
    public bool ProtectQuickConnect { get; set; }

    /// <summary>
    /// Observe session list/revoke routes. Playback commands stay out of scope.
    /// </summary>
    public bool ObserveSessions { get; set; }

    public string CaptchaProvider { get; set; }

    public string CaptchaSiteKey { get; set; }

    public string CaptchaSecret { get; set; }

    public bool CaptchaEnforceWeb { get; set; }

    public bool CaptchaFailOpen { get; set; }

    /// <summary>
    /// When true, clients the classifier cannot identify (no recognizable User-Agent) must
    /// supply a valid challenge token too. TV apps stay exempt because they are recognized.
    /// Off by default: a bot that spoofs a TV app User-Agent still bypasses the challenge,
    /// but this option closes the path for bots that send no recognizable UA at all.
    /// </summary>
    public bool CaptchaChallengeUnknown { get; set; }

    /// <summary>
    /// When true, a client that claims to be a TV or mobile app in its User-Agent
    /// but sends no DeviceId in the Jellyfin authorization header is downgraded
    /// to Unknown. Real Jellyfin apps always send a DeviceId; bots that spoof
    /// a TV User-Agent usually don't. This closes the User-Agent spoofing path
    /// for bots that don't send a proper authorization header. Off by default —
    /// some older or custom clients may not send a DeviceId.
    /// </summary>
    public bool StrictDeviceFingerprint { get; set; }

    /// <summary>
    /// When true, repeated password sign-in attempts wait before Jellyfin sees them.
    /// Playback is never delayed. Off until an administrator enables it.
    /// </summary>
    public bool PasswordDelayEnabled { get; set; }

    public string PasswordDelayStepsSeconds { get; set; }

    public int PasswordDelayCeilingSeconds { get; set; }

    public int PasswordDelayWindowMinutes { get; set; }

    public int PasswordDelayAfterFailures { get; set; }

    public bool PasswordDelayRequireVerifiedAddress { get; set; }

    public bool PasswordDelaySkipPrivilegedNetworks { get; set; }

    /// <summary>
    /// When true, a clearly distributed spray pauses one username inside the plugin.
    /// The Jellyfin account is not disabled, and the pause ends by itself.
    /// </summary>
    public bool AccountCooldownEnabled { get; set; }

    public int AccountCooldownMinutes { get; set; }

    public int AccountCooldownDistinctIps { get; set; }

    public int AccountCooldownFailures { get; set; }

    public int AccountCooldownWindowMinutes { get; set; }

    public bool AccountCooldownSkipPrivilegedNetworks { get; set; }

    /// <summary>
    /// When true, the plugin reads each account's Jellyfin lockout counter and warns near that account's own limit.
    /// The counter is never changed. A limit of -1 or any non-positive value means lockout is off for that account.
    /// </summary>
    public bool LockoutWatchEnabled { get; set; }

    public int LockoutWatchRemaining { get; set; }

    public int LockoutWatchCooldownMinutes { get; set; }

    /// <summary>
    /// When true, a successful sign-in from an unseen address, or too many concurrent sessions, raises an alert.
    /// Nothing is logged out until an administrator uses the button. Playing sessions are left alone.
    /// </summary>
    public bool SessionWatchEnabled { get; set; }

    public int SessionWatchConcurrent { get; set; }

    public int SessionWatchCooldownMinutes { get; set; }

    public bool SessionWatchRequireVerifiedAddress { get; set; }

    public bool SessionWatchSkipPrivilegedNetworks { get; set; }

    public bool EdgeChannelEnabled { get; set; }

    public string EdgeSharedKey { get; set; }

    public bool EdgeRestrictToTrustedPeers { get; set; }

    /// <summary>
    /// When true, the dashboard shows a paste snippet for Nginx, Caddy, or Cloudflare.
    /// The plugin does not write those files. Playback routes are not included.
    /// </summary>
    public bool EdgeSnippetEnabled { get; set; }

    public string EdgeSnippetTarget { get; set; }

    public string EdgeSnippetUpstream { get; set; }

    public int EdgeSnippetAuthPerMinute { get; set; }

    public int EdgeSnippetBurst { get; set; }

    public bool EdgeSnippetIncludeBlocklist { get; set; }

    public string LocalGeoFile { get; set; }

    /// <summary>
    /// Administrator country block rows. Each holds editable CIDR ranges; an enabled row
    /// blocks matching sign-in addresses exactly like a manual ban, so admin and monitoring
    /// networks stay safe. Off by default.
    /// </summary>
    public List<GeoBlockRule> GeoBlocks { get; set; }

    /// <summary>
    /// When true, requests to the allowlist of enumeration endpoints (/Users,
    /// /Items, /System/Info, /Library, and similar collection routes) are
    /// counted per address. An address that crosses the failure or breadth
    /// thresholds raises a Reconnaissance event. Playback, images, downloads,
    /// and static assets are never counted. Off by default.
    /// </summary>
    public bool ReconWatchEnabled { get; set; }

    /// <summary>
    /// When true and <see cref="ReconWatchEnabled"/> is on, an address that
    /// crosses the scan threshold receives 429 rate-limit responses on
    /// enumeration endpoints for <see cref="ReconCooldownMinutes"/>. Requires
    /// a verified client address and does not apply to admin, monitoring, or
    /// trusted networks. Sign-in and playback paths are unaffected. Off by
    /// default.
    /// </summary>
    public bool ReconEnforce { get; set; }

    /// <summary>Sliding window for scan counting.</summary>
    public int ReconWindowMinutes { get; set; }

    /// <summary>
    /// Failed (4xx) API-surface requests inside the window that mark a scan.
    /// A legitimate client carries a valid token and gets 2xx; a scanner
    /// collects 401/403/404.
    /// </summary>
    public int ReconFailedThreshold { get; set; }

    /// <summary>
    /// Unauthenticated API-surface requests inside the window that mark a
    /// scan when combined with <see cref="ReconDistinctPathMin"/>.
    /// </summary>
    public int ReconUnauthThreshold { get; set; }

    /// <summary>
    /// Minimum distinct probed paths for the unauthenticated-volume crossing,
    /// so a client retrying one endpoint cannot trip the breadth rule.
    /// </summary>
    public int ReconDistinctPathMin { get; set; }

    /// <summary>Minutes the 429 response applies after a scan crosses.</summary>
    public int ReconCooldownMinutes { get; set; }

    public int SchemaVersion { get; set; }
}
